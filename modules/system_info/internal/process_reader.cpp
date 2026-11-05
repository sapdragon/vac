// @binary: a07ed54b
#include "internal/process_reader.hpp"
#include "internal/helpers.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/enum.hpp"
#include "crt/intrinsics.hpp"
#include "process/capture_flags.hpp"
#include "process/process.hpp"
#include "util/wstr.hpp"

namespace vac::workers::system_info
{

VAC_FLAGS( EReadFlags )

namespace
{

constexpr u32 k_cubMaxPathString = ( MAX_PATH - 1 ) * sizeof( wchar_t );
constexpr u32 k_cMaxModules = 1000;

// @orig: 55 8B EC 51 56
BOOL __stdcall IsNative64Process( HANDLE hProcess, BOOL *pbNative64 ) noexcept
{
	*pbNative64 = FALSE;
	if ( g_pImports->IsWow64Process )
	{
		BOOL bSelfWow64 = FALSE;
		BOOL bTargetWow64 = FALSE;
		g_pImports->IsWow64Process( g_pImports->GetCurrentProcess(), &bSelfWow64 );
		if ( bSelfWow64 )
		{
			if ( hProcess == INVALID_HANDLE_VALUE )
			{
				*pbNative64 = TRUE;
			}
			else
			{
				g_pImports->IsWow64Process( hProcess, &bTargetWow64 );
				if ( !bTargetWow64 )
					*pbNative64 = TRUE;
			}
		}
	}
	return TRUE;
}

} // namespace

// @orig: 55 8B EC 51 51
NTSTATUS __stdcall ReadVirtualMemoryAuto( HANDLE hProcess, u64 ulAddress, void *pBuffer, u64 cubRead,
                                          u64 *pcubRead ) noexcept
{
	BOOL bNative64 = FALSE;
	if ( IsNative64Process( hProcess, &bNative64 ) && bNative64 )
	{
		if ( g_pImports->NtWow64ReadVirtualMemory64 )
			return g_pImports->NtWow64ReadVirtualMemory64( hProcess, reinterpret_cast<PVOID64>( ulAddress ), pBuffer,
			                                               cubRead, pcubRead );
		return 0;
	}

	if ( g_pImports->NtReadVirtualMemory )
	{
		ULONG cubDone = 0;
		const NTSTATUS nStatus =
		    g_pImports->NtReadVirtualMemory( hProcess, reinterpret_cast<void *>( static_cast<uptr>( ulAddress ) ),
		                                     pBuffer, static_cast<ULONG>( cubRead ), &cubDone );
		*pcubRead = cubDone;
		return nStatus;
	}
	return 0;
}

// @orig: 56 8B F1 8B 8E
void CProcessReader::Release() noexcept
{
	if ( m_pModules )
		HeapRelease( m_pModules );
	m_pModules = nullptr;
	m_cModules = 0;
	if ( m_pUnused254 )
		HeapRelease( m_pUnused254 );
	if ( m_pUnused27C )
		HeapRelease( m_pUnused27C );
	if ( m_pUnused25C )
		HeapRelease( m_pUnused25C );
	if ( m_pUnused264 )
		HeapRelease( m_pUnused264 );
	if ( m_hProcess != INVALID_HANDLE_VALUE && m_hProcess )
		g_pImports->CloseHandle( m_hProcess );
	memset( this, 0, sizeof( *this ) );
	m_hProcess = INVALID_HANDLE_VALUE;
}

// @orig: 81 EC ? ? ? ? 8A 84 24 ? ? ? ? 53 55 8B D9
EScanStatus CProcessReader::ReadProcess64( u32 unPid, EReadFlags eReadFlags ) noexcept
{
	m_unPid = unPid;
	m_cModules = 0;
	m_unUnused250 = 0;
	m_CreationTime.dwLowDateTime = 0;
	m_CreationTime.dwHighDateTime = 0;

	FILETIME rgTimes[4];
	if ( g_pImports->GetProcessTimes( m_hProcess, &rgTimes[0], &rgTimes[1], &rgTimes[2], &rgTimes[3] ) )
	{
		m_eFlags |= process::ECaptureFlags::Times64;
		m_CreationTime = rgTimes[0];
	}

	const HANDLE hProcess = m_hProcess;
	m_eFlags |= process::ECaptureFlags::Entered64;

	nt::ProcessBasicInformation64_t basicInfo;
	ULONG cubBasicInfo = 0;
	BOOL bNative64 = FALSE;
	if ( IsNative64Process( hProcess, &bNative64 ) && bNative64 )
	{
		if ( g_pImports->NtWow64QueryInformationProcess64 )
			g_pImports->NtWow64QueryInformationProcess64( hProcess, ProcessBasicInformation, &basicInfo,
			                                              sizeof( basicInfo ), &cubBasicInfo );
	}
	else if ( g_pImports->NtQueryInformationProcess )
	{
		ULONG cubReturned = 0;
		g_pImports->NtQueryInformationProcess( hProcess, ProcessBasicInformation, &basicInfo, sizeof( basicInfo ),
		                                       &cubReturned );
		cubBasicInfo = cubReturned;
	}

	if ( cubBasicInfo != sizeof( basicInfo ) )
	{
		GetLastError();
		return EScanStatus::BasicInfoFailed;
	}

	m_unParentPid = static_cast<u32>( basicInfo.m_ulInheritedFromUniqueProcessId );
	m_eFlags |= process::ECaptureFlags::BasicInfo64;
	if ( !basicInfo.m_ulPebBaseAddress )
		return EScanStatus::ProcessReadFailed;

	u64 cubRead = 0;
	m_eFlags |= process::ECaptureFlags::PebAddress64;
	nt::Peb64_t peb;
	ReadVirtualMemoryAuto( m_hProcess, basicInfo.m_ulPebBaseAddress, &peb, sizeof( peb ), &cubRead );
	if ( cubRead != sizeof( peb ) )
		return EScanStatus::PebReadFailed;
	m_eFlags |= process::ECaptureFlags::PebRead64;

	// @note / sapdragon: valve reads 1024 chars out of a 520 byte stack buffer and clears it right after,
	// so only the neighbours in its frame get read. this one is just big enough for that copy
	alignas( 8 ) u8 rgubBuffer[2048];
	wchar_t *pwszBuffer = reinterpret_cast<wchar_t *>( rgubBuffer );

	if ( HasFlag( eReadFlags, EReadFlags::Parameters ) )
	{
		alignas( 8 ) u8 rgubParameters[nt::Arch64_t::k_cubProcessParametersSnapshot];
		const auto &parameters = *reinterpret_cast<const nt::ProcessParameters_t<nt::Arch64_t> *>( rgubParameters );
		ReadVirtualMemoryAuto( m_hProcess, peb.m_ulProcessParameters, rgubParameters, sizeof( rgubParameters ),
		                       &cubRead );
		if ( cubRead != nt::Arch64_t::k_cubProcessParametersSnapshot )
			return EScanStatus::ProcessReadFailed;

		pwszBuffer[MAX_PATH - 1] = 0;

		u32 cubString = k_cubMaxPathString;
		if ( parameters.m_CurrentDirectoryPath.m_cubLength < k_cubMaxPathString )
			cubString = parameters.m_CurrentDirectoryPath.m_cubLength;
		memset( rgubBuffer, 0, MAX_PATH * sizeof( wchar_t ) );
		ReadVirtualMemoryAuto( m_hProcess, parameters.m_CurrentDirectoryPath.m_ulBuffer, rgubBuffer, cubString,
		                       &cubRead );
		if ( cubRead != cubString )
			return EScanStatus::ProcessReadFailed;
		pwszBuffer[parameters.m_CurrentDirectoryPath.m_cubLength > cubString
		               ? MAX_PATH - 1
		               : parameters.m_CurrentDirectoryPath.m_cubLength >> 1] = 0;
		CopyWideClearRest( m_wszCurrentDirectory, pwszBuffer, ARRAYSIZE( m_wszCurrentDirectory ) );

		cubString = k_cubMaxPathString;
		if ( parameters.m_ImagePathName.m_cubLength < k_cubMaxPathString )
			cubString = parameters.m_ImagePathName.m_cubLength;
		memset( rgubBuffer, 0, MAX_PATH * sizeof( wchar_t ) );
		ReadVirtualMemoryAuto( m_hProcess, parameters.m_ImagePathName.m_ulBuffer, rgubBuffer, cubString, &cubRead );
		if ( cubRead != cubString )
			return EScanStatus::ProcessReadFailed;
		pwszBuffer[parameters.m_ImagePathName.m_cubLength > cubString ? MAX_PATH - 1
		                                                              : parameters.m_ImagePathName.m_cubLength >> 1] =
		    0;
		CopyWideClearRest( m_wszImagePath, pwszBuffer, ARRAYSIZE( m_wszImagePath ) );

		cubString = k_cubMaxPathString;
		if ( parameters.m_CommandLine.m_cubLength < k_cubMaxPathString )
			cubString = parameters.m_CommandLine.m_cubLength;
		memset( rgubBuffer, 0, MAX_PATH * sizeof( wchar_t ) );
		ReadVirtualMemoryAuto( m_hProcess, parameters.m_CommandLine.m_ulBuffer, rgubBuffer, cubString, &cubRead );
		if ( cubRead != cubString )
			return EScanStatus::ProcessReadFailed;
		pwszBuffer[parameters.m_CommandLine.m_cubLength > cubString ? MAX_PATH - 1
		                                                            : parameters.m_CommandLine.m_cubLength >> 1] = 0;
		CopyWideClearRest( m_wszCommandLine, pwszBuffer, ARRAYSIZE( m_wszCommandLine ) );
	}

	if ( HasFlag( eReadFlags, EReadFlags::Modules ) )
	{
		nt::PebLdrData64_t loaderData;
		ReadVirtualMemoryAuto( m_hProcess, peb.m_ulLdr, &loaderData, nt::Arch64_t::k_cubPebLdrSnapshot, &cubRead );
		if ( cubRead != nt::Arch64_t::k_cubPebLdrSnapshot )
		{
			m_eFlags |= process::ECaptureFlags::LdrReadFailed;
			return EScanStatus::ProcessReadFailed;
		}

		m_eFlags |= process::ECaptureFlags::LdrRead64;
		const u64 ulFirstEntry = loaderData.m_InLoadOrderModuleList.m_ulFlink;
		if ( !ulFirstEntry )
		{
			m_eFlags |= process::ECaptureFlags::LdrEmpty64;
			return EScanStatus::ProcessReadFailed;
		}

		auto *pEntry = reinterpret_cast<nt::LdrDataTableEntry64_t *>( rgubBuffer );
		ReadVirtualMemoryAuto( m_hProcess, ulFirstEntry, pEntry, nt::Arch64_t::k_cubLdrEntrySnapshot, &cubRead );
		if ( cubRead != nt::Arch64_t::k_cubLdrEntrySnapshot )
		{
			m_eFlags |= process::ECaptureFlags::FirstEntryFailed64;
			return EScanStatus::ProcessReadFailed;
		}

		m_eFlags |= process::ECaptureFlags::FirstEntry64;
		u32 iModule = 0;
		u32 iLoadIndex = 1;
		do
		{
			ProcessModuleEntry_t moduleEntry;
			memset( &moduleEntry, 0, sizeof( moduleEntry ) );
			moduleEntry.m_iLoadIndex = iLoadIndex;
			const u32 iNextLoadIndex = iLoadIndex + 1;
			const u32 cubName = pEntry->m_FullDllName.m_cubLength;
			moduleEntry.m_ulDllBase = pEntry->m_ulDllBase;
			moduleEntry.m_cubSizeOfImage = pEntry->m_cubSizeOfImage;

			wchar_t wszName[262];
			if ( cubName >= k_cubMaxPathString )
			{
				m_eFlags |= process::ECaptureFlags::NameTooLong;
			}
			else
			{
				cubRead = 0;
				ReadVirtualMemoryAuto( m_hProcess, pEntry->m_FullDllName.m_ulBuffer, wszName, cubName, &cubRead );
				if ( cubRead != cubName )
				{
					m_eFlags |= process::ECaptureFlags::NameReadFailed;
				}
				else
				{
					wszName[cubName >> 1] = 0;
					CopyWideClearRest( moduleEntry.m_wszPath, wszName, ARRAYSIZE( moduleEntry.m_wszPath ) );
					const wchar_t *pwszBase = util::wstr::BaseName( moduleEntry.m_wszPath );
					if ( pwszBase )
						CopyWideClearRest( moduleEntry.m_wszName, pwszBase, ARRAYSIZE( moduleEntry.m_wszName ) );
				}
			}

			m_pModules = static_cast<ProcessModuleEntry_t *>(
			    HeapResize( m_pModules, sizeof( ProcessModuleEntry_t ) * ( m_cModules + 1 ) ) );
			memcpy( &m_pModules[m_cModules], &moduleEntry, sizeof( moduleEntry ) );
			++m_cModules;

			const u64 ulNext = pEntry->m_InLoadOrderLinks.m_ulFlink;
			if ( !ulNext || ulNext == ulFirstEntry )
				break;
			ReadVirtualMemoryAuto( m_hProcess, ulNext, pEntry, nt::Arch64_t::k_cubLdrEntrySnapshot, &cubRead );
			if ( cubRead != nt::Arch64_t::k_cubLdrEntrySnapshot || !pEntry->m_ulDllBase )
				break;

			iLoadIndex = iNextLoadIndex;
			++iModule;
		} while ( iModule < k_cMaxModules );
	}
	return EScanStatus::Ok;
}

// @orig: 55 8B EC 8A 45
bool CProcessReader::NextLoaderEntry( u32 ulStop, nt::LdrDataTableEntry32_t *pEntry, EReadFlags eReadFlags ) noexcept
{
	bool bInitOrder = ( static_cast<u8>( eReadFlags ) >> 7 ) != 0;
	u32 ulNext;
	if ( HasFlag( eReadFlags, EReadFlags::WalkLoadOrder ) )
	{
		ulNext = pEntry->m_InLoadOrderLinks.m_ulFlink;
	}
	else if ( !HasFlag( eReadFlags, EReadFlags::WalkInitOrder ) )
	{
		bInitOrder = false;
		ulNext = pEntry->m_InMemoryOrderLinks.m_ulFlink;
	}
	else
	{
		ulNext = pEntry->m_InInitializationOrderLinks.m_ulFlink;
	}

	if ( !ulNext || ulNext == ulStop )
		return false;

	if ( !HasFlag( eReadFlags, EReadFlags::WalkLoadOrder ) )
		ulNext -= bInitOrder ? 16 : 8;

	SIZE_T cubRead = 0;
	g_pImports->ReadProcessMemory( m_hProcess, reinterpret_cast<LPCVOID>( static_cast<uptr>( ulNext ) ), pEntry,
	                               nt::Arch32_t::k_cubLdrEntrySnapshot, &cubRead );
	if ( cubRead != nt::Arch32_t::k_cubLdrEntrySnapshot )
	{
		m_eFlags |= process::ECaptureFlags::EntryReadFailed;
		return false;
	}
	return true;
}

// @orig: 81 EC ? ? ? ? 8A 84 24 ? ? ? ? 53 55 56
EScanStatus CProcessReader::ReadProcess( u32 unPid, EReadFlags eReadFlags ) noexcept
{
	m_eFlags = process::ECaptureFlags::None;
	m_CreationTime.dwLowDateTime = 0;
	m_CreationTime.dwHighDateTime = 0;

	m_hProcess = g_pImports->OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, unPid );
	if ( ( g_pSession->m_OsVersion.dwPlatformId != VER_PLATFORM_WIN32_NT ||
	       g_pSession->m_OsVersion.dwMajorVersion < 6 ) &&
	     ( !m_hProcess || m_hProcess == INVALID_HANDLE_VALUE ) )
	{
		m_hProcess = g_pImports->OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, unPid );
	}

	if ( !m_hProcess )
	{
		m_unLastError = g_pImports->GetLastError();
		return EScanStatus::ProcessOpenFailed;
	}

	m_unPid = unPid;
	m_cModules = 0;
	m_unUnused250 = 0;
	m_eFlags |= process::ECaptureFlags::Opened;
	ULONG cubImageName = 1;

	FILETIME rgTimes[4];
	if ( g_pImports->GetProcessTimes( m_hProcess, &rgTimes[0], &rgTimes[1], &rgTimes[2], &rgTimes[3] ) )
	{
		m_eFlags |= process::ECaptureFlags::Times;
		m_CreationTime = rgTimes[0];
	}

	BOOL bNative64 = FALSE;
	IsNative64Process( GetCurrentProcess(), &bNative64 );
	m_bSelfIsWow64 = bNative64 != FALSE;
	bNative64 = FALSE;
	IsNative64Process( m_hProcess, &bNative64 );
	m_bTargetIsNative64 = bNative64 != FALSE;
	g_pImports->CloseHandle( m_hProcess );

	m_hProcess = g_pImports->OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, unPid );
	if ( !m_hProcess )
	{
		m_eFlags |= process::ECaptureFlags::ReopenFailed;
		m_unLastError = g_pImports->GetLastError();
		return EScanStatus::ProcessReopenFailed;
	}

	m_eFlags |= process::ECaptureFlags::Reopened;
	if ( m_bTargetIsNative64 )
	{
		m_eFlags |= process::ECaptureFlags::Cross64;
		return ReadProcess64( unPid, eReadFlags );
	}

	nt::ProcessBasicInformation32_t basicInfo;
	ULONG cubBasicInfo = 0;
	g_pImports->NtQueryInformationProcess( m_hProcess, ProcessBasicInformation, &basicInfo, sizeof( basicInfo ),
	                                       &cubBasicInfo );
	if ( cubBasicInfo != sizeof( basicInfo ) )
		return EScanStatus::BasicInfoFailed;

	m_eFlags |= process::ECaptureFlags::BasicInfo;
	m_unParentPid = basicInfo.m_ulInheritedFromUniqueProcessId;

	if ( !basicInfo.m_ulPebBaseAddress )
	{
		alignas( 8 ) u8 rgubImageName[MAX_PATH * sizeof( wchar_t )];
		reinterpret_cast<wchar_t *>( rgubImageName )[MAX_PATH - 1] = 0;
		g_pImports->NtQueryInformationProcess( m_hProcess, ProcessImageFileName, rgubImageName, sizeof( rgubImageName ),
		                                       &cubImageName );
		if ( cubImageName )
			CopyWideClearRest( m_wszImagePath, reinterpret_cast<const wchar_t *>( rgubImageName + 8 ),
			                   ARRAYSIZE( m_wszImagePath ) );
		return EScanStatus::NoPeb;
	}

	SIZE_T cubRead = 0;
	m_eFlags |= process::ECaptureFlags::PebAddress;
	g_pImports->ReadProcessMemory( m_hProcess,
	                               reinterpret_cast<LPCVOID>( static_cast<uptr>( basicInfo.m_ulPebBaseAddress ) ),
	                               &m_Peb, sizeof( nt::Peb32_t ), &cubRead );
	if ( cubRead != sizeof( nt::Peb32_t ) )
		return EScanStatus::PebReadFailed;

	m_eFlags |= process::ECaptureFlags::PebRead;

	wchar_t wszBuffer[1024];
	if ( HasFlag( eReadFlags, EReadFlags::Parameters ) )
	{
		g_pImports->ReadProcessMemory( m_hProcess,
		                               reinterpret_cast<LPCVOID>( static_cast<uptr>( m_Peb.m_ulProcessParameters ) ),
		                               &m_Parameters, nt::Arch32_t::k_cubProcessParametersSnapshot, &cubRead );
		if ( cubRead != nt::Arch32_t::k_cubProcessParametersSnapshot )
			return EScanStatus::ProcessReadFailed;

		u32 cubString = m_Parameters.m_CurrentDirectoryPath.m_cubLength;
		if ( cubString >= sizeof( wszBuffer ) - sizeof( wchar_t ) )
			cubString = sizeof( wszBuffer ) - sizeof( wchar_t );
		memset( wszBuffer, 0, sizeof( wszBuffer ) );
		g_pImports->ReadProcessMemory(
		    m_hProcess,
		    reinterpret_cast<LPCVOID>( static_cast<uptr>( m_Parameters.m_CurrentDirectoryPath.m_ulBuffer ) ), wszBuffer,
		    cubString, &cubRead );
		if ( cubRead != cubString )
			return EScanStatus::ProcessReadFailed;
		wszBuffer[m_Parameters.m_CurrentDirectoryPath.m_cubLength > cubString
		              ? ARRAYSIZE( wszBuffer ) - 1
		              : m_Parameters.m_CurrentDirectoryPath.m_cubLength >> 1] = 0;
		CopyWideClearRest( m_wszCurrentDirectory, wszBuffer, ARRAYSIZE( m_wszCurrentDirectory ) );

		cubString = m_Parameters.m_ImagePathName.m_cubLength;
		if ( cubString >= sizeof( wszBuffer ) - sizeof( wchar_t ) )
			cubString = sizeof( wszBuffer ) - sizeof( wchar_t );
		memset( wszBuffer, 0, sizeof( wszBuffer ) );
		g_pImports->ReadProcessMemory(
		    m_hProcess, reinterpret_cast<LPCVOID>( static_cast<uptr>( m_Parameters.m_ImagePathName.m_ulBuffer ) ),
		    wszBuffer, cubString, &cubRead );
		if ( cubRead != cubString )
			return EScanStatus::ProcessReadFailed;
		wszBuffer[m_Parameters.m_ImagePathName.m_cubLength > cubString
		              ? ARRAYSIZE( wszBuffer ) - 1
		              : m_Parameters.m_ImagePathName.m_cubLength >> 1] = 0;
		CopyWideClearRest( m_wszImagePath, wszBuffer, ARRAYSIZE( m_wszImagePath ) );

		cubString = sizeof( wszBuffer ) - sizeof( wchar_t );
		if ( m_Parameters.m_CommandLine.m_cubLength < sizeof( wszBuffer ) - sizeof( wchar_t ) )
			cubString = m_Parameters.m_CommandLine.m_cubLength;
		memset( wszBuffer, 0, sizeof( wszBuffer ) );
		g_pImports->ReadProcessMemory(
		    m_hProcess, reinterpret_cast<LPCVOID>( static_cast<uptr>( m_Parameters.m_CommandLine.m_ulBuffer ) ),
		    wszBuffer, cubString, &cubRead );
		if ( cubRead != cubString )
			return EScanStatus::ProcessReadFailed;
		wszBuffer[m_Parameters.m_CommandLine.m_cubLength > cubString ? ARRAYSIZE( wszBuffer ) - 1
		                                                             : m_Parameters.m_CommandLine.m_cubLength >> 1] = 0;
		CopyWideClearRest( m_wszCommandLine, wszBuffer, ARRAYSIZE( m_wszCommandLine ) );
	}

	nt::PebLdrData32_t loaderData;
	g_pImports->ReadProcessMemory( m_hProcess, reinterpret_cast<LPCVOID>( static_cast<uptr>( m_Peb.m_ulLdr ) ),
	                               &loaderData, nt::Arch32_t::k_cubPebLdrSnapshot, &cubRead );
	if ( cubRead != nt::Arch32_t::k_cubPebLdrSnapshot )
	{
		m_eFlags |= process::ECaptureFlags::LdrReadFailed;
		return EScanStatus::ProcessReadFailed;
	}

	m_eFlags |= process::ECaptureFlags::LdrRead;
	if ( HasFlag( eReadFlags, EReadFlags::Modules ) )
	{
		u32 ulStop = loaderData.m_InLoadOrderModuleList.m_ulFlink;
		nt::LdrDataTableEntry32_t entry;
		entry.m_InLoadOrderLinks.m_ulFlink = loaderData.m_InLoadOrderModuleList.m_ulFlink;
		entry.m_InInitializationOrderLinks.m_ulFlink = loaderData.m_InInitializationOrderModuleList.m_ulFlink;
		entry.m_InMemoryOrderLinks.m_ulFlink = loaderData.m_InMemoryOrderModuleList.m_ulFlink;
		if ( !HasFlag( eReadFlags, EReadFlags::WalkLoadOrder ) )
		{
			ulStop = HasFlag( eReadFlags, EReadFlags::WalkInitOrder )
			             ? loaderData.m_InInitializationOrderModuleList.m_ulFlink
			             : loaderData.m_InMemoryOrderModuleList.m_ulFlink;
		}

		if ( !NextLoaderEntry( 0, &entry, eReadFlags ) )
		{
			m_eFlags |= process::ECaptureFlags::FirstEntryFailed;
			return EScanStatus::ProcessReadFailed;
		}

		i32 cRemaining = k_cMaxModules;
		m_eFlags |= process::ECaptureFlags::FirstEntry;
		wchar_t wszName[MAX_PATH];
		for ( ;; )
		{
			--cRemaining;
			ProcessModuleEntry_t moduleEntry;
			memset( &moduleEntry, 0, sizeof( moduleEntry ) );
			const u32 cubName = entry.m_FullDllName.m_cubLength;
			moduleEntry.m_ulDllBase = static_cast<u64>( static_cast<i64>( static_cast<i32>( entry.m_ulDllBase ) ) );
			moduleEntry.m_iLoadIndex = cubImageName;
			moduleEntry.m_cubSizeOfImage = 4096;
			++cubImageName;

			if ( cubName >= k_cubMaxPathString )
			{
				m_eFlags |= process::ECaptureFlags::NameTooLong;
			}
			else
			{
				cubRead = 0;
				g_pImports->ReadProcessMemory(
				    m_hProcess, reinterpret_cast<LPCVOID>( static_cast<uptr>( entry.m_FullDllName.m_ulBuffer ) ),
				    wszName, cubName, &cubRead );
				if ( cubRead == cubName )
				{
					wszName[cubName >> 1] = 0;
					CopyWideClearRest( moduleEntry.m_wszPath, wszName, ARRAYSIZE( moduleEntry.m_wszPath ) );
					const wchar_t *pwszBase = util::wstr::BaseName( moduleEntry.m_wszPath );
					if ( pwszBase )
						CopyWideClearRest( moduleEntry.m_wszName, pwszBase, ARRAYSIZE( moduleEntry.m_wszName ) );
				}
				else
				{
					m_eFlags |= process::ECaptureFlags::NameReadFailed;
				}
			}

			m_pModules = static_cast<ProcessModuleEntry_t *>(
			    HeapResize( m_pModules, sizeof( ProcessModuleEntry_t ) * ( m_cModules + 1 ) ) );
			memcpy( &m_pModules[m_cModules], &moduleEntry, sizeof( moduleEntry ) );
			++m_cModules;

			if ( !NextLoaderEntry( ulStop, &entry, eReadFlags ) || !entry.m_ulDllBase )
				break;
			if ( cRemaining <= 0 )
			{
				--cRemaining;
				break;
			}
		}
		if ( !cRemaining )
			return EScanStatus::TooManyModules;
	}
	return EScanStatus::Ok;
}

} // namespace vac::workers::system_info
