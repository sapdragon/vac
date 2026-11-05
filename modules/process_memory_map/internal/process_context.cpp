// @binary: 8d88e017
#include "internal/process_context.hpp"
#include "core/vac_util.hpp"
#include "crt/intrinsics.hpp"
#include "util/wstr.hpp"

namespace vac::workers::process_memory_map
{

namespace
{

constexpr u32 k_cubMaxLdrName = 0x206;
constexpr i32 k_cMaxLdrEntries = 1000;

struct LdrName_t
{
	wchar_t m_rgwch[( k_cubMaxLdrName + 8 ) / sizeof( wchar_t )];
};

void StoreLdrName( LdrModule_t &module, LdrName_t &name, u32 cubName ) noexcept
{
	name.m_rgwch[cubName >> 1] = 0;
	CopyWideFilled( module.m_wszFullPath, name.m_rgwch, MAX_PATH );
	// @note / sapdragon: valve's copy reads past the string into the stack here. only the path is ever read back
	const wchar_t *pwszBase = util::wstr::BaseName( module.m_wszFullPath );
	if ( pwszBase )
		util::wstr::Copy( module.m_wszBaseName, pwszBase, 256 );
}

void AppendLdrModule( ProcessContext_t &context, const LdrModule_t &module ) noexcept
{
	context.m_pModules = static_cast<LdrModule_t *>(
	    ResizeOrAlloc( context.m_pModules, sizeof( LdrModule_t ) * ( context.m_cModules + 1 ) ) );
	context.m_pModules[context.m_cModules] = module;
	++context.m_cModules;
}

// @orig: 81 EC ? ? ? ? 8A 84 24 ? ? ? ? 53 55 8B D9
EScanStatus CaptureLdr64( ProcessContext_t &context, u32 unPid, const SystemImports_t *pImports ) noexcept
{
	context.m_unPid = unPid;
	context.m_ulCreateTime = 0;
	context.m_cModules = 0;
	context.m_pModules = nullptr;

	FILETIME rgTimes[4];
	if ( pImports->GetProcessTimes( context.m_hProcess, &rgTimes[0], &rgTimes[1], &rgTimes[2], &rgTimes[3] ) )
	{
		context.m_eCaptureFlags |= process::ECaptureFlags::Times64;
		memcpy( &context.m_ulCreateTime, &rgTimes[0], sizeof( context.m_ulCreateTime ) );
	}

	const HANDLE hProcess = context.m_hProcess;
	context.m_eCaptureFlags |= process::ECaptureFlags::Entered64;

	nt::ProcessBasicInformation64_t basic;
	ULONG cubBasic = 0;
	if ( IsCross64( pImports, hProcess ) )
	{
		if ( pImports->NtWow64QueryInformationProcess64 )
			pImports->NtWow64QueryInformationProcess64( hProcess, ProcessBasicInformation, &basic, sizeof( basic ),
			                                            &cubBasic );
	}
	else if ( pImports->NtQueryInformationProcess )
	{
		ULONG cubNative = 0;
		pImports->NtQueryInformationProcess( hProcess, ProcessBasicInformation, &basic, sizeof( basic ), &cubNative );
		cubBasic = cubNative;
	}
	if ( cubBasic != sizeof( basic ) )
		return EScanStatus::BasicInfoFailed;

	context.m_unParentPid = static_cast<u32>( basic.m_ulInheritedFromUniqueProcessId );
	context.m_eCaptureFlags |= process::ECaptureFlags::BasicInfo64;
	if ( !basic.m_ulPebBaseAddress )
		return EScanStatus::ProcessReadFailed;

	u64 cubRead = 0;
	nt::Peb64_t peb;
	context.m_eCaptureFlags |= process::ECaptureFlags::PebAddress64;
	ReadVirtualMemory( pImports, hProcess, basic.m_ulPebBaseAddress, &peb, sizeof( nt::Peb64_t ), &cubRead );
	if ( cubRead != sizeof( nt::Peb64_t ) )
		return EScanStatus::PebReadFailed;
	context.m_eCaptureFlags |= process::ECaptureFlags::PebRead64;

	nt::PebLdrData64_t ldr;
	ReadVirtualMemory( pImports, hProcess, peb.m_ulLdr, &ldr, nt::Arch64_t::k_cubPebLdrSnapshot, &cubRead );
	if ( cubRead != nt::Arch64_t::k_cubPebLdrSnapshot )
	{
		context.m_eCaptureFlags |= process::ECaptureFlags::LdrReadFailed;
		return EScanStatus::ProcessReadFailed;
	}
	context.m_eCaptureFlags |= process::ECaptureFlags::LdrRead64;

	const u64 ulFirst = ldr.m_InLoadOrderModuleList.m_ulFlink;
	if ( !ulFirst )
	{
		context.m_eCaptureFlags |= process::ECaptureFlags::LdrEmpty64;
		return EScanStatus::ProcessReadFailed;
	}

	nt::LdrDataTableEntry64_t entry;
	ReadVirtualMemory( pImports, hProcess, ulFirst, &entry, nt::Arch64_t::k_cubLdrEntrySnapshot, &cubRead );
	if ( cubRead != nt::Arch64_t::k_cubLdrEntrySnapshot )
	{
		context.m_eCaptureFlags |= process::ECaptureFlags::FirstEntryFailed64;
		return EScanStatus::ProcessReadFailed;
	}
	context.m_eCaptureFlags |= process::ECaptureFlags::FirstEntry64;

	u32 unIndex = 1;
	for ( i32 iEntry = 0; iEntry < k_cMaxLdrEntries; ++iEntry )
	{
		LdrModule_t module;
		memset( &module, 0, sizeof( module ) );
		module.m_unIndex = unIndex;
		module.m_ulBase = entry.m_ulDllBase;
		module.m_cubImage = entry.m_cubSizeOfImage;
		++unIndex;

		const u32 cubName = entry.m_FullDllName.m_cubLength;
		if ( cubName >= k_cubMaxLdrName )
		{
			context.m_eCaptureFlags |= process::ECaptureFlags::NameTooLong;
		}
		else
		{
			LdrName_t name;
			cubRead = 0;
			ReadVirtualMemory( pImports, hProcess, entry.m_FullDllName.m_ulBuffer, name.m_rgwch, cubName, &cubRead );
			if ( cubRead != cubName )
				context.m_eCaptureFlags |= process::ECaptureFlags::NameReadFailed;
			else
				StoreLdrName( module, name, cubName );
		}

		AppendLdrModule( context, module );

		const u64 ulNext = entry.m_InLoadOrderLinks.m_ulFlink;
		if ( !ulNext || ulNext == ulFirst )
			break;

		ReadVirtualMemory( pImports, hProcess, ulNext, &entry, nt::Arch64_t::k_cubLdrEntrySnapshot, &cubRead );
		if ( cubRead != nt::Arch64_t::k_cubLdrEntrySnapshot )
			break;
		// @note / sapdragon: the list head reads as an entry with no DllBase, that is the real end of the list
		if ( !entry.m_ulDllBase )
			break;
	}
	return EScanStatus::Ok;
}

// @orig: 55 8B EC 8A 45
bool ReadNextLdrEntry32( ProcessContext_t &context, u32 unStop, nt::LdrDataTableEntry32_t &entry,
                         const SystemImports_t *pImports ) noexcept
{
	const u32 unNext = entry.m_InLoadOrderLinks.m_ulFlink;
	if ( !unNext || unNext == unStop )
		return false;

	SIZE_T cubRead = 0;
	pImports->ReadProcessMemory( context.m_hProcess, reinterpret_cast<LPCVOID>( static_cast<uptr>( unNext ) ), &entry,
	                             nt::Arch32_t::k_cubLdrEntrySnapshot, &cubRead );
	if ( cubRead != nt::Arch32_t::k_cubLdrEntrySnapshot )
	{
		context.m_eCaptureFlags |= process::ECaptureFlags::EntryReadFailed;
		return false;
	}
	return true;
}

} // namespace

// @orig: 52 85 C9 74
void *ResizeOrAlloc( void *pMemory, usize cubSize ) noexcept
{
	if ( pMemory )
		return ::HeapReAlloc( ::GetProcessHeap(), 0, pMemory, cubSize );
	return ::HeapAlloc( ::GetProcessHeap(), 0, cubSize );
}

// @note / sapdragon: copies all cChars even past the terminator, then clears the tail. a source that long is left
// without a terminator. not wstr::Copy
// @orig: 53 56 57 8B 7C 24
void CopyWideFilled( wchar_t *pwszDst, const wchar_t *pwszSrc, u32 cChars ) noexcept
{
	memcpy( pwszDst, pwszSrc, cChars * sizeof( wchar_t ) );
	const u32 cchSrc = static_cast<u32>( lstrlenW( pwszSrc ) );
	if ( cChars > cchSrc )
		memset( pwszDst + cchSrc, 0, ( cChars - cchSrc ) * sizeof( wchar_t ) );
}

// @orig: 53 55 57 8B E9
int CompareNoCase( const wchar_t *pwszA, const wchar_t *pwszB, u32 cMaxChars ) noexcept
{
	u32 cchA = static_cast<u32>( lstrlenW( pwszA ) );
	u32 cchB = static_cast<u32>( lstrlenW( pwszB ) );
	if ( cchA > cMaxChars )
		cchA = cMaxChars;
	if ( cchB > cMaxChars )
		cchB = cMaxChars;
	return CompareStringW( LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, pwszA, static_cast<int>( cchA ), pwszB,
	                       static_cast<int>( cchB ) ) -
	       CSTR_EQUAL;
}

// @orig: 55 8B EC 51 56
bool IsCross64( const SystemImports_t *pImports, HANDLE hProcess ) noexcept
{
	if ( !pImports->IsWow64Process )
		return false;

	BOOL bSelf = FALSE;
	BOOL bTarget = FALSE;
	pImports->IsWow64Process( pImports->GetCurrentProcess(), &bSelf );
	if ( !bSelf )
		return false;
	if ( hProcess == INVALID_HANDLE_VALUE )
		return true;
	pImports->IsWow64Process( hProcess, &bTarget );
	return !bTarget;
}

// @orig: 55 8B EC 51 51 56
NTSTATUS QueryVirtualMemory( const SystemImports_t *pImports, HANDLE hProcess, u64 ulAddress,
                             EMemoryInformationClass eClass, void *pOutput, u32 cubOutput, u64 *pcubReturned ) noexcept
{
	if ( IsCross64( pImports, hProcess ) )
	{
		if ( pImports->NtWow64QueryVirtualMemory64 )
			return pImports->NtWow64QueryVirtualMemory64( hProcess, reinterpret_cast<PVOID64>( ulAddress ),
			                                              static_cast<DWORD>( eClass ), pOutput, cubOutput,
			                                              reinterpret_cast<PULONG64>( pcubReturned ) );
	}
	else if ( pImports->NtQueryVirtualMemory )
	{
		ULONG cubReturned = 0;
		const NTSTATUS nStatus =
		    pImports->NtQueryVirtualMemory( hProcess, reinterpret_cast<void *>( static_cast<uptr>( ulAddress ) ),
		                                    static_cast<DWORD>( eClass ), pOutput, cubOutput, &cubReturned );
		*pcubReturned = cubReturned;
		return nStatus;
	}
	return 0;
}

// @orig: 55 8B EC 51 51 83 65
NTSTATUS ReadVirtualMemory( const SystemImports_t *pImports, HANDLE hProcess, u64 ulAddress, void *pOutput,
                            u32 cubOutput, u64 *pcubRead ) noexcept
{
	if ( IsCross64( pImports, hProcess ) )
	{
		if ( pImports->NtWow64ReadVirtualMemory64 )
			return pImports->NtWow64ReadVirtualMemory64( hProcess, reinterpret_cast<PVOID64>( ulAddress ), pOutput,
			                                             cubOutput, reinterpret_cast<PULONG64>( pcubRead ) );
	}
	else if ( pImports->NtReadVirtualMemory )
	{
		ULONG cubRead = 0;
		const NTSTATUS nStatus = pImports->NtReadVirtualMemory(
		    hProcess, reinterpret_cast<void *>( static_cast<uptr>( ulAddress ) ), pOutput, cubOutput, &cubRead );
		*pcubRead = cubRead;
		return nStatus;
	}
	return 0;
}

// @orig: 55 8B EC 83 EC ? 56 8D 45
u32 QueryBasicInformation( const SystemImports_t *pImports, HANDLE hProcess, u64 ulAddress,
                           MEMORY_BASIC_INFORMATION64 *pInformation ) noexcept
{
	u64 cubReturned = 0;
	if ( IsCross64( pImports, hProcess ) )
	{
		QueryVirtualMemory( pImports, hProcess, ulAddress, EMemoryInformationClass::Basic, pInformation,
		                    sizeof( MEMORY_BASIC_INFORMATION64 ), &cubReturned );
		return static_cast<u32>( cubReturned );
	}

	MEMORY_BASIC_INFORMATION32 native;
	QueryVirtualMemory( pImports, hProcess, ulAddress, EMemoryInformationClass::Basic, &native, sizeof( native ),
	                    &cubReturned );
	if ( cubReturned != sizeof( native ) )
		return static_cast<u32>( cubReturned );

	// @note / sapdragon: both addresses are sign extended, so a large address aware target gets a high dword of all
	// ones. the region size is not
	pInformation->AllocationBase = static_cast<u64>( static_cast<i64>( static_cast<i32>( native.AllocationBase ) ) );
	pInformation->AllocationProtect = native.AllocationProtect;
	pInformation->BaseAddress = static_cast<u64>( static_cast<i64>( static_cast<i32>( native.BaseAddress ) ) );
	pInformation->RegionSize = native.RegionSize;
	pInformation->Protect = native.Protect;
	pInformation->State = native.State;
	pInformation->Type = native.Type;
	return sizeof( MEMORY_BASIC_INFORMATION64 );
}

// @note / sapdragon: the name always comes from offset 8, the native UNICODE_STRING layout, also for a 64-bit target
// @orig: 55 8B EC 81 EC
u32 GetMappedFileName( const SystemImports_t *pImports, HANDLE hProcess, u64 ulAddress, wchar_t *pwszName ) noexcept
{
	wchar_t rgwchBuffer[( 8 + 1072 ) / sizeof( wchar_t )];
	const u32 cubQuery = sizeof( UNICODE_STRING ) + MAX_PATH * sizeof( wchar_t );
	u64 cubReturned = cubQuery;
	if ( QueryVirtualMemory( pImports, hProcess, ulAddress, EMemoryInformationClass::MappedFilename, rgwchBuffer,
	                         cubQuery, &cubReturned ) != 0 )
	{
		pImports->GetLastError();
		return 0;
	}

	*pwszName = 0;
	if ( cubReturned <= 8 )
		return 0;

	const u32 cchReturned = static_cast<u32>( cubReturned ) >> 1;
	if ( cchReturned >= MAX_PATH )
		return 0;

	rgwchBuffer[cchReturned] = 0;
	CopyWideFilled( pwszName, rgwchBuffer + 4, MAX_PATH );
	return cchReturned;
}

// @orig: 81 EC ? ? ? ? 53 55 33 C0
bool DevicePathToDosPath( const SystemImports_t *pImports, wchar_t *pwszPath ) noexcept
{
	wchar_t wszDrives[MAX_PATH];
	wszDrives[0] = 0;
	if ( !pImports->GetLogicalDriveStringsW( 250, wszDrives ) )
		return false;

	const wchar_t *pwchDrive = wszDrives;
	wchar_t wszDrive[4] = L"C:";
	wchar_t wszDevice[MAX_PATH];
	u32 cchDevice;
	wchar_t wchDrive = wszDrives[0];
	for ( ;; )
	{
		wszDrive[0] = wchDrive;
		if ( pImports->QueryDosDeviceW( wszDrive, wszDevice, MAX_PATH ) )
		{
			cchDevice = static_cast<u32>( lstrlenW( wszDevice ) );
			if ( cchDevice < MAX_PATH && CompareNoCase( pwszPath, wszDevice, cchDevice ) == 0 )
				break;
		}
		while ( *pwchDrive++ )
		{
		}
		wchDrive = *pwchDrive;
		if ( !wchDrive )
			return false;
	}

	wchar_t wszJoined[MAX_PATH];
	wszJoined[0] = 0;
	lstrcatW( wszJoined, wszDrive );
	lstrcatW( wszJoined, &pwszPath[cchDevice] );
	CopyWideFilled( pwszPath, wszJoined, MAX_PATH );
	return true;
}

// @orig: 81 EC ? ? ? ? 8A 84 24 ? ? ? ? 53 55 56
EScanStatus OpenProcessAndCaptureLdr( ProcessContext_t &context, u32 unPid, const SystemImports_t *pImports,
                                      const ModuleSession_t *pSession ) noexcept
{
	context.m_eCaptureFlags = process::ECaptureFlags::None;
	context.m_ulCreateTime = 0;

	context.m_hProcess = pImports->OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, unPid );
	if ( ( pSession->m_OsVersion.dwPlatformId != VER_PLATFORM_WIN32_NT ||
	       pSession->m_OsVersion.dwMajorVersion < HIBYTE( _WIN32_WINNT_VISTA ) ) &&
	     ( !context.m_hProcess || context.m_hProcess == INVALID_HANDLE_VALUE ) )
		context.m_hProcess = pImports->OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, unPid );

	if ( !context.m_hProcess )
	{
		context.m_unLastError = pImports->GetLastError();
		return EScanStatus::ProcessOpenFailed;
	}

	context.m_unPid = unPid;
	context.m_cModules = 0;
	context.m_eCaptureFlags |= process::ECaptureFlags::Opened;
	context.m_pModules = nullptr;

	FILETIME rgTimes[4];
	if ( pImports->GetProcessTimes( context.m_hProcess, &rgTimes[0], &rgTimes[1], &rgTimes[2], &rgTimes[3] ) )
	{
		context.m_eCaptureFlags |= process::ECaptureFlags::Times;
		memcpy( &context.m_ulCreateTime, &rgTimes[0], sizeof( context.m_ulCreateTime ) );
	}

	context.m_bSelfWow64 = IsCross64( pImports, ::GetCurrentProcess() );
	context.m_bCross64 = IsCross64( pImports, context.m_hProcess );
	pImports->CloseHandle( context.m_hProcess );

	context.m_hProcess = pImports->OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, unPid );
	if ( !context.m_hProcess )
	{
		context.m_eCaptureFlags |= process::ECaptureFlags::ReopenFailed;
		context.m_unLastError = pImports->GetLastError();
		return EScanStatus::ProcessReopenFailed;
	}
	context.m_eCaptureFlags |= process::ECaptureFlags::Reopened;

	if ( context.m_bCross64 )
	{
		context.m_eCaptureFlags |= process::ECaptureFlags::Cross64;
		return CaptureLdr64( context, unPid, pImports );
	}

	nt::ProcessBasicInformation32_t basic;
	ULONG cubBasic = 0;
	pImports->NtQueryInformationProcess( context.m_hProcess, ProcessBasicInformation, &basic, sizeof( basic ),
	                                     &cubBasic );
	if ( cubBasic != sizeof( basic ) )
		return EScanStatus::BasicInfoFailed;

	context.m_eCaptureFlags |= process::ECaptureFlags::BasicInfo;
	context.m_unParentPid = basic.m_ulInheritedFromUniqueProcessId;
	if ( !basic.m_ulPebBaseAddress )
	{
		// @note / sapdragon: valve stores this name in a field nothing reads back
		u8 rgubImageName[520];
		ULONG cubImageName = 1;
		pImports->NtQueryInformationProcess( context.m_hProcess, ProcessImageFileName, rgubImageName,
		                                     sizeof( rgubImageName ), &cubImageName );
		return EScanStatus::NoPeb;
	}

	SIZE_T cubRead = 0;
	context.m_eCaptureFlags |= process::ECaptureFlags::PebAddress;
	pImports->ReadProcessMemory( context.m_hProcess,
	                             reinterpret_cast<LPCVOID>( static_cast<uptr>( basic.m_ulPebBaseAddress ) ),
	                             &context.m_Peb, sizeof( nt::Peb32_t ), &cubRead );
	if ( cubRead != sizeof( nt::Peb32_t ) )
		return EScanStatus::PebReadFailed;
	context.m_eCaptureFlags |= process::ECaptureFlags::PebRead;

	nt::PebLdrData32_t ldr;
	pImports->ReadProcessMemory( context.m_hProcess,
	                             reinterpret_cast<LPCVOID>( static_cast<uptr>( context.m_Peb.m_ulLdr ) ), &ldr,
	                             nt::Arch32_t::k_cubPebLdrSnapshot, &cubRead );
	if ( cubRead != nt::Arch32_t::k_cubPebLdrSnapshot )
	{
		context.m_eCaptureFlags |= process::ECaptureFlags::LdrReadFailed;
		return EScanStatus::ProcessReadFailed;
	}
	context.m_eCaptureFlags |= process::ECaptureFlags::LdrRead;

	const u32 unStop = ldr.m_InLoadOrderModuleList.m_ulFlink;
	nt::LdrDataTableEntry32_t entry;
	entry.m_InLoadOrderLinks.m_ulFlink = unStop;
	if ( !ReadNextLdrEntry32( context, 0, entry, pImports ) )
	{
		context.m_eCaptureFlags |= process::ECaptureFlags::FirstEntryFailed;
		return EScanStatus::ProcessReadFailed;
	}
	context.m_eCaptureFlags |= process::ECaptureFlags::FirstEntry;

	u32 unIndex = 1;
	i32 cEntriesLeft = k_cMaxLdrEntries;
	for ( ;; )
	{
		--cEntriesLeft;

		LdrModule_t module;
		memset( &module, 0, sizeof( module ) );
		// @note / sapdragon: 4096 and not SizeOfImage, this path only matches an address in the first page of a
		// module. the base is sign extended too
		module.m_ulBase = static_cast<u64>( static_cast<i64>( static_cast<i32>( entry.m_ulDllBase ) ) );
		module.m_unIndex = unIndex++;
		module.m_cubImage = 0x1000;

		const u32 cubName = entry.m_FullDllName.m_cubLength;
		if ( cubName >= k_cubMaxLdrName )
		{
			context.m_eCaptureFlags |= process::ECaptureFlags::NameTooLong;
		}
		else
		{
			LdrName_t name;
			cubRead = 0;
			pImports->ReadProcessMemory(
			    context.m_hProcess, reinterpret_cast<LPCVOID>( static_cast<uptr>( entry.m_FullDllName.m_ulBuffer ) ),
			    name.m_rgwch, cubName, &cubRead );
			if ( cubRead == cubName )
				StoreLdrName( module, name, cubName );
			else
				context.m_eCaptureFlags |= process::ECaptureFlags::NameReadFailed;
		}

		AppendLdrModule( context, module );

		if ( !ReadNextLdrEntry32( context, unStop, entry, pImports ) || !entry.m_ulDllBase )
			break;
		if ( cEntriesLeft <= 0 )
		{
			--cEntriesLeft;
			break;
		}
	}

	// @note / sapdragon: only when entry 1000 was the last one read, running over the limit reports success
	return cEntriesLeft == 0 ? EScanStatus::TooManyModules : EScanStatus::Ok;
}

// @orig: 56 8B F1 8B 8E
void ReleaseProcessContext( ProcessContext_t &context, const SystemImports_t *pImports ) noexcept
{
	util::HeapFree( context.m_pModules );
	context.m_pModules = nullptr;
	context.m_cModules = 0;

	if ( context.m_hProcess != INVALID_HANDLE_VALUE && context.m_hProcess )
		pImports->CloseHandle( context.m_hProcess );

	memset( &context, 0, sizeof( context ) );
	context.m_hProcess = INVALID_HANDLE_VALUE;
}

// @orig: 8B 44 24 ? 3B 81
const LdrModule_t *GetLdrModule( const ProcessContext_t &context, i32 iModule ) noexcept
{
	return iModule < context.m_cModules ? &context.m_pModules[iModule] : nullptr;
}

// @orig: 53 55 56 8B B1
const LdrModule_t *FindLdrModuleContaining( const ProcessContext_t &context, u64 ulAddress ) noexcept
{
	for ( i32 iModule = 0; iModule < context.m_cModules; ++iModule )
	{
		const LdrModule_t &module = context.m_pModules[iModule];
		if ( ulAddress >= module.m_ulBase && ulAddress < module.m_ulBase + module.m_cubImage )
			return &module;
	}
	return nullptr;
}

// @orig: 53 55 56 57 8B F9 33 F6 39 B7
const LdrModule_t *FindLdrModuleByPath( const ProcessContext_t &context, const wchar_t *pwszPath ) noexcept
{
	for ( i32 iModule = 0; iModule < context.m_cModules; ++iModule )
	{
		const LdrModule_t &module = context.m_pModules[iModule];
		if ( CompareNoCase( module.m_wszFullPath, pwszPath, 520 ) == 0 )
			return &module;
	}
	return nullptr;
}

// @orig: 55 8B EC 83 E4 ? 83 EC
bool WalkAllocation( const SystemImports_t *pImports, HANDLE hProcess, AllocationWalk_t &walk ) noexcept
{
	bool bReservedAfterCommit = false;
	const u64 ulPrevious = walk.m_ulPreviousStart;
	walk.m_ulFirstCommitted = 0;
	walk.m_ulLastCommitEnd = 0;
	walk.m_ulCommitPrefixEnd = 0;
	walk.m_cubTotal = 0;
	walk.m_unProtectUnion = 0;
	walk.m_unExecuteProtectUnion = 0;
	walk.m_cRegions = 0;
	walk.m_cCommittedRegions = 0;
	walk.m_cubCommitPrefix = 0;
	if ( ulPrevious && walk.m_ulCursor <= ulPrevious )
		return false;

	walk.m_ulPreviousStart = walk.m_ulCursor;
	walk.m_ulQueryAddress = walk.m_ulCursor;
	if ( QueryBasicInformation( pImports, hProcess, walk.m_ulCursor, &walk.m_First ) !=
	     sizeof( MEMORY_BASIC_INFORMATION64 ) )
	{
		walk.m_unLastError = pImports->GetLastError();
		return false;
	}
	if ( walk.m_First.RegionSize == 0xFFFFFFFFu )
		return false;

	u64 ulAddress = walk.m_ulCursor;
	walk.m_ulQueryAddress = ulAddress;
	MEMORY_BASIC_INFORMATION64 region;
	u32 cubQueried = QueryBasicInformation( pImports, hProcess, ulAddress, &region );
	walk.m_ulCursor = ulAddress;
	for ( ;; )
	{
		if ( cubQueried != sizeof( MEMORY_BASIC_INFORMATION64 ) )
		{
			walk.m_unLastError = pImports->GetLastError();
			return true;
		}
		if ( region.AllocationBase != walk.m_First.AllocationBase )
			return true;

		const u64 ulNext = ulAddress + region.RegionSize;
		if ( region.State == MEM_FREE )
		{
			walk.m_cubTotal += region.RegionSize;
			walk.m_ulCursor = ulNext;
			walk.m_unProtectUnion |= region.Protect;
			++walk.m_cRegions;
			return true;
		}

		if ( region.State == MEM_RESERVE )
		{
			if ( walk.m_ulFirstCommitted )
			{
				walk.m_cubTotal += region.RegionSize;
				bReservedAfterCommit = true;
			}
			++walk.m_cRegions;
		}
		else if ( region.State == MEM_COMMIT )
		{
			walk.m_ulLastCommitEnd = ulNext;
			if ( !bReservedAfterCommit )
			{
				walk.m_cubCommitPrefix += region.RegionSize;
				walk.m_ulCommitPrefixEnd = ulNext;
			}
			if ( !walk.m_ulFirstCommitted )
				walk.m_ulFirstCommitted = ulAddress;
			walk.m_cubTotal += region.RegionSize;
			walk.m_unProtectUnion |= region.Protect;
			if ( region.Protect & k_unPageExecuteAny )
				walk.m_unExecuteProtectUnion |= region.Protect;
			++walk.m_cRegions;
			++walk.m_cCommittedRegions;
		}

		if ( ulNext <= ulAddress )
			return true;

		walk.m_ulQueryAddress = ulNext;
		ulAddress = ulNext;
		cubQueried = QueryBasicInformation( pImports, hProcess, ulNext, &region );
		walk.m_ulCursor = ulNext;
	}
}

} // namespace vac::workers::process_memory_map
