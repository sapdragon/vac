// @binary: a8848995
#include "internal/types.hpp"
#include "bootstrap/bootstrap.hpp"
#include "crt/intrinsics.hpp"
#include "process/process.hpp"
#include "util/encoding.hpp"
#include "util/hashing.hpp"
#include "util/strings.hpp"
#include "util/wstr.hpp"

namespace vac::workers::process_file_identity
{

namespace
{

constexpr u32 k_unProfileProcessHash = 0xBDE1D93C;
constexpr u32 k_cubMaxRemoteString = 0x206;
constexpr u32 k_cMaxModules = 1000;
constexpr u32 k_cubMappedNameQuery = 528;
constexpr DWORD k_unMemoryMappedFilename = 2;

// @orig: 55 8B EC 51 56
bool IsCrossBitnessTarget( HANDLE hProcess ) noexcept
{
	if ( !g_pImports->IsWow64Process )
		return false;

	BOOL bSelfWow64 = FALSE;
	BOOL bTargetWow64 = FALSE;
	g_pImports->IsWow64Process( g_pImports->GetCurrentProcess(), &bSelfWow64 );
	if ( !bSelfWow64 )
		return false;
	if ( hProcess == INVALID_HANDLE_VALUE )
		return true;

	g_pImports->IsWow64Process( hProcess, &bTargetWow64 );
	return !bTargetWow64;
}

// @orig: 55 8B EC 51 51 83 65
void ReadVirtualMemory( HANDLE hProcess, u64 ulAddress, void *pOutput, u32 cubOutput, u64 *pcubRead ) noexcept
{
	if ( IsCrossBitnessTarget( hProcess ) )
	{
		if ( g_pImports->NtWow64ReadVirtualMemory64 )
			g_pImports->NtWow64ReadVirtualMemory64( hProcess, reinterpret_cast<PVOID64>( ulAddress ), pOutput,
			                                        cubOutput, pcubRead );
	}
	else if ( g_pImports->NtReadVirtualMemory )
	{
		ULONG cubRead = 0;
		g_pImports->NtReadVirtualMemory( hProcess, reinterpret_cast<void *>( static_cast<uptr>( ulAddress ) ), pOutput,
		                                 cubOutput, &cubRead );
		*pcubRead = cubRead;
	}
}

// @orig: 55 8B EC 51 51 56
NTSTATUS QueryMappedFileName( HANDLE hProcess, u64 ulAddress, void *pOutput, u64 *pcubOutput ) noexcept
{
	if ( IsCrossBitnessTarget( hProcess ) )
	{
		if ( g_pImports->NtWow64QueryVirtualMemory64 )
			return g_pImports->NtWow64QueryVirtualMemory64( hProcess, reinterpret_cast<PVOID64>( ulAddress ),
			                                                k_unMemoryMappedFilename, pOutput, k_cubMappedNameQuery,
			                                                pcubOutput );
	}
	else if ( g_pImports->NtQueryVirtualMemory )
	{
		ULONG cubOutput = 0;
		const NTSTATUS nStatus =
		    g_pImports->NtQueryVirtualMemory( hProcess, reinterpret_cast<void *>( static_cast<uptr>( ulAddress ) ),
		                                      k_unMemoryMappedFilename, pOutput, k_cubMappedNameQuery, &cubOutput );
		*pcubOutput = cubOutput;
		return nStatus;
	}
	return 0;
}

// @orig: 55 8B EC 81 EC
u32 GetMappedFilePath( HANDLE hProcess, u64 ulAddress, wchar_t *pwszPath ) noexcept
{
	wchar_t rgwchBuffer[540];
	u64 cubOutput = k_cubMappedNameQuery;
	if ( QueryMappedFileName( hProcess, ulAddress, rgwchBuffer, &cubOutput ) )
	{
		g_pImports->GetLastError();
		return 0;
	}

	*pwszPath = 0;
	if ( cubOutput <= sizeof( UNICODE_STRING ) )
		return 0;

	const u32 cChars = static_cast<u32>( cubOutput ) >> 1;
	if ( cChars >= 0x200 )
		return 0;

	// @note / sapdragon: skips a 32-bit UNICODE_STRING even when the target is 64-bit, where the header is twice as
	// big. the name comes out as garbage then, keep it
	rgwchBuffer[cChars] = 0;
	CopyWideFixed( pwszPath, rgwchBuffer + sizeof( UNICODE_STRING ) / sizeof( wchar_t ), k_cPathChars );
	return cChars;
}

// @orig: inlined
bool ReadParameterString32( HANDLE hProcess, const nt::UnicodeString32_t &string, wchar_t *pwszOutput,
                            SIZE_T *pcubRead ) noexcept
{
	// @note / sapdragon: 260 chars are used, the rest is there because CopyWideFixed reads the whole count
	wchar_t wszBuffer[500];
	const u32 cubString = string.m_cubLength < k_cubMaxRemoteString ? string.m_cubLength : k_cubMaxRemoteString;
	memset( wszBuffer, 0, sizeof( wszBuffer ) );

	g_pImports->ReadProcessMemory( hProcess, reinterpret_cast<const void *>( static_cast<uptr>( string.m_ulBuffer ) ),
	                               wszBuffer, cubString, pcubRead );
	if ( *pcubRead != cubString )
		return false;

	wszBuffer[string.m_cubLength > cubString ? MAX_PATH - 1 : string.m_cubLength >> 1] = 0;
	CopyWideFixed( pwszOutput, wszBuffer, ARRAYSIZE( wszBuffer ) );
	return true;
}

// @orig: inlined
bool ReadParameterString64( HANDLE hProcess, const nt::UnicodeString64_t &string, wchar_t *pwszOutput,
                            u64 *pcubRead ) noexcept
{
	wchar_t wszBuffer[500];
	const u32 cubString = string.m_cubLength < k_cubMaxRemoteString ? string.m_cubLength : k_cubMaxRemoteString;
	memset( wszBuffer, 0, sizeof( wszBuffer ) );

	ReadVirtualMemory( hProcess, string.m_ulBuffer, wszBuffer, cubString, pcubRead );
	if ( *pcubRead != cubString )
		return false;

	wszBuffer[string.m_cubLength > cubString ? MAX_PATH - 1 : string.m_cubLength >> 1] = 0;
	CopyWideFixed( pwszOutput, wszBuffer, ARRAYSIZE( wszBuffer ) );
	return true;
}

// @orig: inlined
void AppendModuleRecord( ProcessCapture_t &capture, const ModuleRecord_t &record ) noexcept
{
	capture.m_pModules = static_cast<ModuleRecord_t *>(
	    ReallocateHeap( capture.m_pModules, sizeof( ModuleRecord_t ) * ( capture.m_cModules + 1 ) ) );
	capture.m_pModules[capture.m_cModules] = record;
	++capture.m_cModules;
}

// @orig: 81 EC ? ? ? ? 8A 84 24 ? ? ? ? 53 55 8B D9
EScanStatus CaptureProcess64( ProcessCapture_t &capture, u32 unPid, ECaptureOptions eOptions ) noexcept
{
	capture.m_unPid = unPid;
	capture.m_CreationTime = {};
	capture.m_cModules = 0;

	FILETIME creation, exit, kernel, user;
	if ( g_pImports->GetProcessTimes( capture.m_hProcess, &creation, &exit, &kernel, &user ) )
	{
		capture.m_eProgress |= process::ECaptureFlags::Times64;
		capture.m_CreationTime = creation;
	}

	const HANDLE hProcess = capture.m_hProcess;
	capture.m_eProgress |= process::ECaptureFlags::Entered64;

	nt::ProcessBasicInformation64_t basic;
	ULONG cubBasic = 0;
	if ( IsCrossBitnessTarget( hProcess ) )
	{
		if ( g_pImports->NtWow64QueryInformationProcess64 )
			g_pImports->NtWow64QueryInformationProcess64( hProcess, ProcessBasicInformation, &basic, sizeof( basic ),
			                                              &cubBasic );
	}
	else if ( g_pImports->NtQueryInformationProcess )
	{
		ULONG cubReturned = 0;
		g_pImports->NtQueryInformationProcess( hProcess, ProcessBasicInformation, &basic, sizeof( basic ),
		                                       &cubReturned );
		cubBasic = cubReturned;
	}
	if ( cubBasic != sizeof( basic ) )
	{
		::GetLastError();
		return EScanStatus::BasicInfoFailed;
	}

	capture.m_unParentPid = static_cast<u32>( basic.m_ulInheritedFromUniqueProcessId );
	capture.m_eProgress |= process::ECaptureFlags::BasicInfo64;
	if ( !basic.m_ulPebBaseAddress )
		return EScanStatus::ProcessReadFailed;

	u64 cubRead = 0;
	capture.m_eProgress |= process::ECaptureFlags::PebAddress64;

	nt::Peb64_t peb;
	ReadVirtualMemory( hProcess, basic.m_ulPebBaseAddress, &peb, sizeof( nt::Peb64_t ), &cubRead );
	if ( cubRead != sizeof( nt::Peb64_t ) )
		return EScanStatus::PebReadFailed;
	capture.m_eProgress |= process::ECaptureFlags::PebRead64;

	if ( HasFlag( eOptions, ECaptureOptions::Parameters ) )
	{
		union
		{
			nt::ProcessParameters64_t m_Parameters;
			u8 m_rgub[nt::Arch64_t::k_cubProcessParametersSnapshot];
		} parameters;
		ReadVirtualMemory( hProcess, peb.m_ulProcessParameters, &parameters,
		                   nt::Arch64_t::k_cubProcessParametersSnapshot, &cubRead );
		if ( cubRead != nt::Arch64_t::k_cubProcessParametersSnapshot )
			return EScanStatus::ProcessReadFailed;

		if ( !ReadParameterString64( hProcess, parameters.m_Parameters.m_CurrentDirectoryPath,
		                             capture.m_wszCurrentDirectory, &cubRead ) )
			return EScanStatus::ProcessReadFailed;
		if ( !ReadParameterString64( hProcess, parameters.m_Parameters.m_ImagePathName, capture.m_wszImagePath,
		                             &cubRead ) )
			return EScanStatus::ProcessReadFailed;
		if ( !ReadParameterString64( hProcess, parameters.m_Parameters.m_CommandLine, capture.m_wszCommandLine,
		                             &cubRead ) )
			return EScanStatus::ProcessReadFailed;
	}

	if ( HasFlag( eOptions, ECaptureOptions::Modules ) )
	{
		nt::PebLdrData64_t ldr;
		ReadVirtualMemory( hProcess, peb.m_ulLdr, &ldr, nt::Arch64_t::k_cubPebLdrSnapshot, &cubRead );
		if ( cubRead != nt::Arch64_t::k_cubPebLdrSnapshot )
		{
			capture.m_eProgress |= process::ECaptureFlags::LdrReadFailed;
			return EScanStatus::ProcessReadFailed;
		}

		capture.m_eProgress |= process::ECaptureFlags::LdrRead64;
		const u64 ulFirst = ldr.m_InLoadOrderModuleList.m_ulFlink;
		if ( !ulFirst )
		{
			capture.m_eProgress |= process::ECaptureFlags::LdrEmpty64;
			return EScanStatus::ProcessReadFailed;
		}

		nt::LdrDataTableEntry64_t entry;
		ReadVirtualMemory( hProcess, ulFirst, &entry, nt::Arch64_t::k_cubLdrEntrySnapshot, &cubRead );
		if ( cubRead != nt::Arch64_t::k_cubLdrEntrySnapshot )
		{
			capture.m_eProgress |= process::ECaptureFlags::FirstEntryFailed64;
			return EScanStatus::ProcessReadFailed;
		}
		capture.m_eProgress |= process::ECaptureFlags::FirstEntry64;

		ModuleRecord_t record;
		wchar_t wszName[262];
		for ( u32 iModule = 0; iModule < k_cMaxModules; ++iModule )
		{
			memset( &record, 0, sizeof( record ) );
			const u32 cubName = entry.m_FullDllName.m_cubLength;
			record.m_ulBase = entry.m_ulDllBase;
			record.m_unTag = entry.m_cubSizeOfImage;
			if ( cubName >= k_cubMaxRemoteString )
			{
				capture.m_eProgress |= process::ECaptureFlags::NameTooLong;
			}
			else
			{
				cubRead = 0;
				ReadVirtualMemory( hProcess, entry.m_FullDllName.m_ulBuffer, wszName, cubName, &cubRead );
				if ( cubRead != cubName )
				{
					capture.m_eProgress |= process::ECaptureFlags::NameReadFailed;
				}
				else
				{
					wszName[cubName >> 1] = 0;
					CopyWideFixed( record.m_wszPath, wszName, ARRAYSIZE( record.m_wszPath ) );
					const wchar_t *pwszBase = util::wstr::BaseName( record.m_wszPath );
					if ( pwszBase )
						CopyWideFixed( record.m_wszName, pwszBase, ARRAYSIZE( record.m_wszName ) );
				}
			}

			AppendModuleRecord( capture, record );

			const u64 ulNext = entry.m_InLoadOrderLinks.m_ulFlink;
			if ( !ulNext || ulNext == ulFirst )
				break;

			ReadVirtualMemory( hProcess, ulNext, &entry, nt::Arch64_t::k_cubLdrEntrySnapshot, &cubRead );
			if ( cubRead != nt::Arch64_t::k_cubLdrEntrySnapshot || !entry.m_ulDllBase )
				break;
		}
	}

	return EScanStatus::Ok;
}

} // namespace

// @orig: 8B 54 24 ? 8B C2
ECaptureOptions EncodeCaptureFlags( ECaptureRequest eRequest ) noexcept
{
	const u16 unRequest = static_cast<u16>( eRequest );
	ECaptureOptions eOptions = ECaptureOptions::None;
	if ( unRequest & static_cast<u16>( ECaptureRequest::Modules ) )
		eOptions |= ECaptureOptions::Modules;
	if ( unRequest & static_cast<u16>( ECaptureRequest::Unused040 ) )
		eOptions |= ECaptureOptions::Unused02;
	if ( unRequest & static_cast<u16>( ECaptureRequest::Parameters ) )
		eOptions |= ECaptureOptions::Parameters;
	if ( unRequest & static_cast<u16>( ECaptureRequest::Unused080 ) )
		eOptions |= ECaptureOptions::Unused08;
	if ( unRequest & static_cast<u16>( ECaptureRequest::Unused100 ) )
		eOptions |= ECaptureOptions::Unused10;
	if ( unRequest & static_cast<u16>( ECaptureRequest::Unused200 ) )
		eOptions |= ECaptureOptions::Unused20;
	return eOptions;
}

// @orig: 56 68 ? ? ? ? 8B F1
void InitProcessCapture( ProcessCapture_t &capture ) noexcept
{
	memset( &capture, 0, sizeof( capture ) );
	capture.m_hProcess = INVALID_HANDLE_VALUE;
}

// @orig: 56 8B F1 8B 8E
void FreeProcessCapture( ProcessCapture_t &capture ) noexcept
{
	if ( capture.m_pModules )
		::HeapFree( ::GetProcessHeap(), 0, capture.m_pModules );
	capture.m_pModules = nullptr;
	capture.m_cModules = 0;

	if ( capture.m_hProcess != INVALID_HANDLE_VALUE && capture.m_hProcess )
		g_pImports->CloseHandle( capture.m_hProcess );

	memset( &capture, 0, sizeof( capture ) );
	capture.m_hProcess = INVALID_HANDLE_VALUE;
}

// @orig: 81 EC ? ? ? ? 8A 84 24 ? ? ? ? 53 55 56
EScanStatus CaptureProcess( ProcessCapture_t &capture, u32 unPid, ECaptureOptions eOptions ) noexcept
{
	capture.m_eProgress = process::ECaptureFlags::None;
	capture.m_CreationTime = {};

	capture.m_hProcess = g_pImports->OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, unPid );
	if ( ( g_pSession->m_OsVersion.dwPlatformId != VER_PLATFORM_WIN32_NT ||
	       g_pSession->m_OsVersion.dwMajorVersion < 6 ) &&
	     ( !capture.m_hProcess || capture.m_hProcess == INVALID_HANDLE_VALUE ) )
	{
		capture.m_hProcess = g_pImports->OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, unPid );
	}

	if ( !capture.m_hProcess )
	{
		capture.m_unLastError = g_pImports->GetLastError();
		return EScanStatus::ProcessOpenFailed;
	}

	capture.m_eProgress |= process::ECaptureFlags::Opened;
	capture.m_unPid = unPid;
	capture.m_cModules = 0;

	FILETIME creation, exit, kernel, user;
	if ( g_pImports->GetProcessTimes( capture.m_hProcess, &creation, &exit, &kernel, &user ) )
	{
		capture.m_eProgress |= process::ECaptureFlags::Times;
		capture.m_CreationTime = creation;
	}

	capture.m_bSelfIsWow64 = IsCrossBitnessTarget( ::GetCurrentProcess() );
	capture.m_bTargetIsNative64 = IsCrossBitnessTarget( capture.m_hProcess );

	g_pImports->CloseHandle( capture.m_hProcess );
	capture.m_hProcess = g_pImports->OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, unPid );
	if ( !capture.m_hProcess )
	{
		capture.m_eProgress |= process::ECaptureFlags::ReopenFailed;
		capture.m_unLastError = g_pImports->GetLastError();
		return EScanStatus::ProcessReopenFailed;
	}

	capture.m_eProgress |= process::ECaptureFlags::Reopened;
	if ( capture.m_bTargetIsNative64 )
	{
		capture.m_eProgress |= process::ECaptureFlags::Cross64;
		return CaptureProcess64( capture, unPid, eOptions );
	}

	nt::ProcessBasicInformation32_t basic;
	ULONG cubBasic = 0;
	g_pImports->NtQueryInformationProcess( capture.m_hProcess, ProcessBasicInformation, &basic, sizeof( basic ),
	                                       &cubBasic );
	if ( cubBasic != sizeof( basic ) )
		return EScanStatus::BasicInfoFailed;

	const HANDLE hProcess = capture.m_hProcess;
	capture.m_eProgress |= process::ECaptureFlags::BasicInfo;
	capture.m_unParentPid = basic.m_ulInheritedFromUniqueProcessId;

	if ( !basic.m_ulPebBaseAddress )
	{
		wchar_t rgwchImageName[MAX_PATH];
		ULONG cubImageName = 0;
		rgwchImageName[MAX_PATH - 1] = 0;
		g_pImports->NtQueryInformationProcess( hProcess, ProcessImageFileName, rgwchImageName, sizeof( rgwchImageName ),
		                                       &cubImageName );
		if ( cubImageName )
			CopyWideFixed( capture.m_wszImagePath, rgwchImageName + sizeof( UNICODE_STRING ) / sizeof( wchar_t ),
			               ARRAYSIZE( capture.m_wszImagePath ) );
		return EScanStatus::NoPeb;
	}

	SIZE_T cubRead = 0;
	capture.m_eProgress |= process::ECaptureFlags::PebAddress;
	g_pImports->ReadProcessMemory( hProcess,
	                               reinterpret_cast<const void *>( static_cast<uptr>( basic.m_ulPebBaseAddress ) ),
	                               &capture.m_Peb, sizeof( nt::Peb32_t ), &cubRead );
	if ( cubRead != sizeof( nt::Peb32_t ) )
		return EScanStatus::PebReadFailed;
	capture.m_eProgress |= process::ECaptureFlags::PebRead;

	if ( HasFlag( eOptions, ECaptureOptions::Parameters ) )
	{
		g_pImports->ReadProcessMemory(
		    hProcess, reinterpret_cast<const void *>( static_cast<uptr>( capture.m_Peb.m_ulProcessParameters ) ),
		    capture.m_rgubParameters, nt::Arch32_t::k_cubProcessParametersSnapshot, &cubRead );
		if ( cubRead != nt::Arch32_t::k_cubProcessParametersSnapshot )
			return EScanStatus::ProcessReadFailed;

		if ( !ReadParameterString32( hProcess, capture.m_Parameters.m_CurrentDirectoryPath,
		                             capture.m_wszCurrentDirectory, &cubRead ) )
			return EScanStatus::ProcessReadFailed;
		if ( !ReadParameterString32( hProcess, capture.m_Parameters.m_ImagePathName, capture.m_wszImagePath,
		                             &cubRead ) )
			return EScanStatus::ProcessReadFailed;
		if ( !ReadParameterString32( hProcess, capture.m_Parameters.m_CommandLine, capture.m_wszCommandLine,
		                             &cubRead ) )
			return EScanStatus::ProcessReadFailed;
	}

	nt::PebLdrData32_t ldr;
	g_pImports->ReadProcessMemory( hProcess,
	                               reinterpret_cast<const void *>( static_cast<uptr>( capture.m_Peb.m_ulLdr ) ), &ldr,
	                               offsetof( nt::PebLdrData32_t, m_InInitializationOrderModuleList ), &cubRead );
	if ( cubRead != offsetof( nt::PebLdrData32_t, m_InInitializationOrderModuleList ) )
	{
		capture.m_eProgress |= process::ECaptureFlags::LdrReadFailed;
		return EScanStatus::ProcessReadFailed;
	}

	const u32 unFirst = ldr.m_InMemoryOrderModuleList.m_ulFlink;
	capture.m_eProgress |= process::ECaptureFlags::LdrRead;
	if ( !unFirst )
	{
		capture.m_eProgress |= process::ECaptureFlags::LdrEmpty64;
		return EScanStatus::ProcessReadFailed;
	}

	if ( HasFlag( eOptions, ECaptureOptions::Modules ) )
	{
		nt::LdrDataTableEntry32_t entry;
		g_pImports->ReadProcessMemory( hProcess,
		                               reinterpret_cast<const void *>( static_cast<uptr>(
		                                   unFirst - offsetof( nt::LdrDataTableEntry32_t, m_InMemoryOrderLinks ) ) ),
		                               &entry, nt::Arch32_t::k_cubLdrEntrySnapshot, &cubRead );
		capture.m_eProgress |= process::ECaptureFlags::FirstEntry;
		if ( cubRead != nt::Arch32_t::k_cubLdrEntrySnapshot )
		{
			capture.m_eProgress |= process::ECaptureFlags::FirstEntryFailed64;
			return EScanStatus::ProcessReadFailed;
		}

		ModuleRecord_t record;
		wchar_t wszName[k_cubMaxRemoteString / sizeof( wchar_t ) + 1];
		i32 cLeft = k_cMaxModules;
		for ( ;; )
		{
			--cLeft;
			memset( &record, 0, sizeof( record ) );
			const u32 cubName = entry.m_FullDllName.m_cubLength;

			// @note / sapdragon: the base goes through a signed int on the way to 64 bits, like the original
			record.m_ulBase = static_cast<u64>( static_cast<i64>( static_cast<i32>( entry.m_ulDllBase ) ) );
			record.m_unTag = 0x1000;
			if ( cubName >= k_cubMaxRemoteString )
			{
				capture.m_eProgress |= process::ECaptureFlags::NameTooLong;
			}
			else
			{
				cubRead = 0;
				g_pImports->ReadProcessMemory(
				    hProcess, reinterpret_cast<const void *>( static_cast<uptr>( entry.m_FullDllName.m_ulBuffer ) ),
				    wszName, cubName, &cubRead );
				if ( cubRead == cubName )
				{
					wszName[cubName >> 1] = 0;
					CopyWideFixed( record.m_wszPath, wszName, ARRAYSIZE( record.m_wszPath ) );
					const wchar_t *pwszBase = util::wstr::BaseName( record.m_wszPath );
					if ( pwszBase )
						CopyWideFixed( record.m_wszName, pwszBase, ARRAYSIZE( record.m_wszName ) );
				}
				else
				{
					capture.m_eProgress |= process::ECaptureFlags::NameReadFailed;
				}
			}

			AppendModuleRecord( capture, record );

			const u32 unNext = entry.m_InMemoryOrderLinks.m_ulFlink;
			if ( !unNext || unNext == unFirst )
				break;

			g_pImports->ReadProcessMemory( hProcess,
			                               reinterpret_cast<const void *>( static_cast<uptr>(
			                                   unNext - offsetof( nt::LdrDataTableEntry32_t, m_InMemoryOrderLinks ) ) ),
			                               &entry, nt::Arch32_t::k_cubLdrEntrySnapshot, &cubRead );
			if ( cubRead != nt::Arch32_t::k_cubLdrEntrySnapshot )
			{
				capture.m_eProgress |= process::ECaptureFlags::EntryReadFailed;
				break;
			}
			if ( !entry.m_ulDllBase )
				break;
			if ( cLeft <= 0 )
			{
				--cLeft;
				break;
			}
		}

		if ( !cLeft )
			return EScanStatus::TooManyModules;
	}

	return EScanStatus::Ok;
}

// @orig: 55 8B EC B8
bool GetFirstModulePath( u32 unPid, wchar_t *pwszPath ) noexcept
{
	ProcessCapture_t capture;
	InitProcessCapture( capture );
	CaptureProcess( capture, unPid, EncodeCaptureFlags( ECaptureRequest::Modules ) );

	const ModuleRecord_t *pModule = static_cast<i32>( capture.m_cModules ) > 0 ? capture.m_pModules : nullptr;
	bool bFound = false;
	if ( pModule )
	{
		if ( GetMappedFilePath( capture.m_hProcess, pModule->m_ulBase, pwszPath ) )
			NtDeviceToDosPath( pwszPath );
		else
			CopyWideFixed( pwszPath, pModule->m_wszPath, k_cPathChars );
		bFound = true;
	}

	FreeProcessCapture( capture );
	return bFound;
}

// @orig: A1 ? ? ? ? 81 EC
void FindProfileProcess( u32 *punPid, u32 *pcFound ) noexcept
{
	process::ForEachSnapshotProcess(
	    g_pImports,
	    [&]( const PROCESSENTRY32W &entry )
	    {
		    char szName[MAX_PATH];
		    util::encoding::WideToUtf8Bounded( g_pImports, entry.szExeFile, szName, sizeof( szName ) );
		    if ( util::hashing::PathHashBytes( reinterpret_cast<const u8 *>( szName ), util::StrLenA( szName ) ) ==
		         k_unProfileProcessHash )
		    {
			    ++*pcFound;
			    *punPid = entry.th32ProcessID;
		    }
		    return true;
	    } );
}

} // namespace vac::workers::process_file_identity
