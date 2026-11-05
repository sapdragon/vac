// @binary: 33211402
#include "../scanner.hpp"
#include "bootstrap/bootstrap.hpp"
#include "crt/intrinsics.hpp"
#include "process/capture_flags.hpp"
#include "process/process.hpp"
#include "util/wstr.hpp"

namespace vac::workers::image_scan
{

namespace
{

constexpr u32 k_cubPeb64Name = ( MAX_PATH - 1 ) * sizeof( wchar_t );
constexpr u32 k_cMaxModules = 1000;

void CopyNameToProbe64( const ProcessProbe_t *pProbe, const nt::UnicodeString64_t &name, wchar_t *pwszDst,
                        u32 cDstChars, bool *pbOk ) noexcept
{
	u32 cubName = k_cubPeb64Name;
	if ( name.m_cubLength < k_cubPeb64Name )
		cubName = name.m_cubLength;

	wchar_t rgwchName[MAX_PATH];
	memset( rgwchName, 0, sizeof( rgwchName ) );

	u64 cubRead = 0;
	ReadTargetMemory( pProbe->m_hProcess, name.m_ulBuffer, rgwchName, cubName, &cubRead );
	if ( cubRead != cubName )
	{
		*pbOk = false;
		return;
	}

	rgwchName[name.m_cubLength > cubName ? 259 : name.m_cubLength >> 1] = 0;
	CopyWideFill( pwszDst, rgwchName, cDstChars );
}

void CopyNameToProbe32( const ProcessProbe_t *pProbe, const nt::UnicodeString32_t &name, wchar_t *pwszDst,
                        u32 cDstChars, bool *pbOk ) noexcept
{
	u32 cubName = name.m_cubLength;
	if ( cubName >= 2046 )
		cubName = 2046;

	wchar_t rgwchName[1024];
	memset( rgwchName, 0, sizeof( rgwchName ) );

	SIZE_T cubRead = 0;
	g_pImports->ReadProcessMemory( pProbe->m_hProcess,
	                               reinterpret_cast<const void *>( static_cast<uptr>( name.m_ulBuffer ) ), rgwchName,
	                               cubName, &cubRead );
	if ( cubRead != cubName )
	{
		*pbOk = false;
		return;
	}

	rgwchName[name.m_cubLength > cubName ? 1023 : name.m_cubLength >> 1] = 0;
	CopyWideFill( pwszDst, rgwchName, cDstChars );
}

void AppendModule( ProcessProbe_t *pProbe, const ProbeModule_t &module ) noexcept
{
	pProbe->m_pModules = static_cast<ProbeModule_t *>(
	    ReallocBytes( pProbe->m_pModules, sizeof( ProbeModule_t ) * ( pProbe->m_cModules + 1 ) ) );
	memcpy( &pProbe->m_pModules[pProbe->m_cModules], &module, sizeof( module ) );
	++pProbe->m_cModules;
}

// @orig: 81 EC ? ? ? ? 8A 84 24 ? ? ? ? 53 55 8B D9
EScanStatus WalkProcess64( ProcessProbe_t *pProbe, u32 unPid, EProbeFlags eFlags ) noexcept
{
	pProbe->m_unPid = unPid;
	pProbe->m_cModules = 0;
	pProbe->m_cThreads = 0;
	pProbe->m_ulCreationTime = 0;

	FILETIME creationTime;
	FILETIME exitTime;
	FILETIME kernelTime;
	FILETIME userTime;
	if ( g_pImports->GetProcessTimes( pProbe->m_hProcess, &creationTime, &exitTime, &kernelTime, &userTime ) )
	{
		pProbe->m_eFlags |= process::ECaptureFlags::Times64;
		memcpy( &pProbe->m_ulCreationTime, &creationTime, sizeof( creationTime ) );
	}

	const HANDLE hProcess = pProbe->m_hProcess;
	pProbe->m_eFlags |= process::ECaptureFlags::Entered64;

	nt::ProcessBasicInformation64_t basicInfo;
	ULONG cubReturned = 0;
	BOOL bCrossBitness = FALSE;
	if ( IsCrossBitnessProcess( hProcess, &bCrossBitness ) && bCrossBitness )
	{
		if ( g_pImports->NtWow64QueryInformationProcess64 )
			g_pImports->NtWow64QueryInformationProcess64( hProcess, ProcessBasicInformation, &basicInfo,
			                                              sizeof( basicInfo ), &cubReturned );
	}
	else if ( g_pImports->NtQueryInformationProcess )
	{
		ULONG cubNative = 0;
		g_pImports->NtQueryInformationProcess( hProcess, ProcessBasicInformation, &basicInfo, sizeof( basicInfo ),
		                                       &cubNative );
		cubReturned = cubNative;
	}
	if ( cubReturned != sizeof( basicInfo ) )
	{
		GetLastError();
		return EScanStatus::BasicInfoFailed;
	}

	pProbe->m_unParentPid = static_cast<u32>( basicInfo.m_ulInheritedFromUniqueProcessId );
	pProbe->m_eFlags |= process::ECaptureFlags::BasicInfo64;
	if ( !basicInfo.m_ulPebBaseAddress )
		return EScanStatus::ProcessReadFailed;

	pProbe->m_eFlags |= process::ECaptureFlags::PebAddress64;

	nt::Peb64_t peb;
	u64 cubRead = 0;
	ReadTargetMemory( pProbe->m_hProcess, basicInfo.m_ulPebBaseAddress, &peb, sizeof( nt::Peb64_t ), &cubRead );
	if ( cubRead != sizeof( nt::Peb64_t ) )
		return EScanStatus::PebReadFailed;
	pProbe->m_eFlags |= process::ECaptureFlags::PebRead64;

	if ( HasFlag( eFlags, EProbeFlags::Parameters ) )
	{
		u8 rgubParameters[nt::Arch64_t::k_cubProcessParametersSnapshot];
		ReadTargetMemory( pProbe->m_hProcess, peb.m_ulProcessParameters, rgubParameters, sizeof( rgubParameters ),
		                  &cubRead );
		if ( cubRead != sizeof( rgubParameters ) )
			return EScanStatus::ProcessReadFailed;

		const auto &parameters = *reinterpret_cast<const nt::ProcessParameters64_t *>( rgubParameters );
		bool bOk = true;
		CopyNameToProbe64( pProbe, parameters.m_CurrentDirectoryPath, pProbe->m_wszCurrentDirectory,
		                   ARRAYSIZE( pProbe->m_wszCurrentDirectory ), &bOk );
		if ( !bOk )
			return EScanStatus::ProcessReadFailed;
		CopyNameToProbe64( pProbe, parameters.m_ImagePathName, pProbe->m_wszImagePath,
		                   ARRAYSIZE( pProbe->m_wszImagePath ), &bOk );
		if ( !bOk )
			return EScanStatus::ProcessReadFailed;
		CopyNameToProbe64( pProbe, parameters.m_CommandLine, pProbe->m_wszCommandLine,
		                   ARRAYSIZE( pProbe->m_wszCommandLine ), &bOk );
		if ( !bOk )
			return EScanStatus::ProcessReadFailed;
	}

	if ( HasFlag( eFlags, EProbeFlags::Modules ) )
	{
		nt::PebLdrData64_t ldr;
		ReadTargetMemory( pProbe->m_hProcess, peb.m_ulLdr, &ldr, nt::Arch64_t::k_cubPebLdrSnapshot, &cubRead );
		if ( cubRead != nt::Arch64_t::k_cubPebLdrSnapshot )
		{
			pProbe->m_eFlags |= process::ECaptureFlags::LdrReadFailed;
			return EScanStatus::ProcessReadFailed;
		}

		pProbe->m_eFlags |= process::ECaptureFlags::LdrRead64;
		const u64 ulFirstEntry = ldr.m_InLoadOrderModuleList.m_ulFlink;
		if ( !ulFirstEntry )
		{
			pProbe->m_eFlags |= process::ECaptureFlags::LdrEmpty64;
			return EScanStatus::ProcessReadFailed;
		}

		u8 rgubEntry[nt::Arch64_t::k_cubLdrEntrySnapshot];
		const auto &entry = *reinterpret_cast<const nt::LdrDataTableEntry64_t *>( rgubEntry );
		ReadTargetMemory( pProbe->m_hProcess, ulFirstEntry, rgubEntry, sizeof( rgubEntry ), &cubRead );
		if ( cubRead != sizeof( rgubEntry ) )
		{
			pProbe->m_eFlags |= process::ECaptureFlags::FirstEntryFailed64;
			return EScanStatus::ProcessReadFailed;
		}
		pProbe->m_eFlags |= process::ECaptureFlags::FirstEntry64;

		u32 iLoadOrder = 1;
		for ( u32 iModule = 0; iModule < k_cMaxModules; ++iModule )
		{
			ProbeModule_t module;
			memset( &module, 0, sizeof( module ) );
			module.m_iLoadOrder = iLoadOrder++;
			const u32 cubName = entry.m_FullDllName.m_cubLength;
			module.m_ulBase = entry.m_ulDllBase;
			module.m_cubImage = entry.m_cubSizeOfImage;
			if ( cubName >= k_cubPeb64Name )
			{
				pProbe->m_eFlags |= process::ECaptureFlags::NameTooLong;
			}
			else
			{
				wchar_t rgwchName[262];
				cubRead = 0;
				ReadTargetMemory( pProbe->m_hProcess, entry.m_FullDllName.m_ulBuffer, rgwchName, cubName, &cubRead );
				if ( cubRead != cubName )
				{
					pProbe->m_eFlags |= process::ECaptureFlags::NameReadFailed;
				}
				else
				{
					rgwchName[cubName >> 1] = 0;
					CopyWideFill( module.m_wszFullName, rgwchName, ARRAYSIZE( module.m_wszFullName ) );
					const wchar_t *pwszBaseName = util::wstr::BaseName( module.m_wszFullName );
					if ( pwszBaseName )
						CopyWideFill( module.m_wszBaseName, pwszBaseName, ARRAYSIZE( module.m_wszBaseName ) );
				}
			}
			AppendModule( pProbe, module );

			const u64 ulNext = entry.m_InLoadOrderLinks.m_ulFlink;
			if ( !ulNext || ulNext == ulFirstEntry )
				break;
			ReadTargetMemory( pProbe->m_hProcess, ulNext, rgubEntry, sizeof( rgubEntry ), &cubRead );
			if ( cubRead != sizeof( rgubEntry ) || !entry.m_ulDllBase )
				break;
		}
	}
	return EScanStatus::Ok;
}

// @orig: 55 8B EC 8A 45
bool ReadNextLdrEntry( ProcessProbe_t *pProbe, u32 unFirstEntry, nt::LdrDataTableEntry32_t *pEntry,
                       EProbeFlags eFlags ) noexcept
{
	const bool bInitOrder = HasFlag( eFlags, EProbeFlags::InitOrder );
	u32 unNext;
	if ( HasFlag( eFlags, EProbeFlags::LoadOrder ) )
		unNext = pEntry->m_InLoadOrderLinks.m_ulFlink;
	else if ( bInitOrder )
		unNext = pEntry->m_InInitializationOrderLinks.m_ulFlink;
	else
		unNext = pEntry->m_InMemoryOrderLinks.m_ulFlink;

	if ( !unNext || unNext == unFirstEntry )
		return false;

	if ( !HasFlag( eFlags, EProbeFlags::LoadOrder ) )
		unNext -= bInitOrder ? offsetof( nt::LdrDataTableEntry32_t, m_InInitializationOrderLinks )
		                     : offsetof( nt::LdrDataTableEntry32_t, m_InMemoryOrderLinks );

	SIZE_T cubRead = 0;
	g_pImports->ReadProcessMemory( pProbe->m_hProcess, reinterpret_cast<const void *>( static_cast<uptr>( unNext ) ),
	                               pEntry, nt::Arch32_t::k_cubLdrEntrySnapshot, &cubRead );
	if ( cubRead != nt::Arch32_t::k_cubLdrEntrySnapshot )
	{
		pProbe->m_eFlags |= process::ECaptureFlags::EntryReadFailed;
		return false;
	}
	return true;
}

} // namespace

// @note / sapdragon: the probe holds Peb32_t, whose Ldr and parameters sit at 0x0C and 0x10. the old rebuild read them
// 4 bytes off. the module size in this branch really is a constant, and the list end is the first entry
// @orig: 81 EC ? ? ? ? 8A 84 24 ? ? ? ? 53 55 56 8B B4 24 ? ? ? ? 8B D9 57 88 44 24 ? 33 ED
EScanStatus WalkProcess( ProcessProbe_t *pProbe, u32 unPid, EProbeFlags eFlags ) noexcept
{
	pProbe->m_eFlags = process::ECaptureFlags::None;
	pProbe->m_ulCreationTime = 0;

	pProbe->m_hProcess = g_pImports->OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, unPid );
	if ( ( g_pSession->m_OsVersion.dwPlatformId != VER_PLATFORM_WIN32_NT ||
	       g_pSession->m_OsVersion.dwMajorVersion < 6 ) &&
	     ( !pProbe->m_hProcess || pProbe->m_hProcess == INVALID_HANDLE_VALUE ) )
	{
		pProbe->m_hProcess = g_pImports->OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, unPid );
	}

	if ( !pProbe->m_hProcess )
	{
		pProbe->m_unLastError = g_pImports->GetLastError();
		return EScanStatus::ProcessOpenFailed;
	}

	pProbe->m_unPid = unPid;
	pProbe->m_cModules = 0;
	pProbe->m_cThreads = 0;
	pProbe->m_eFlags |= process::ECaptureFlags::Opened;

	u32 iLoadOrder = 1;
	FILETIME creationTime;
	FILETIME exitTime;
	FILETIME kernelTime;
	FILETIME userTime;
	if ( g_pImports->GetProcessTimes( pProbe->m_hProcess, &creationTime, &exitTime, &kernelTime, &userTime ) )
	{
		pProbe->m_eFlags |= process::ECaptureFlags::Times;
		memcpy( &pProbe->m_ulCreationTime, &creationTime, sizeof( creationTime ) );
	}

	BOOL bCrossBitness = FALSE;
	IsCrossBitnessProcess( GetCurrentProcess(), &bCrossBitness );
	pProbe->m_bSelfWow64 = bCrossBitness != FALSE;
	bCrossBitness = FALSE;
	IsCrossBitnessProcess( pProbe->m_hProcess, &bCrossBitness );
	pProbe->m_bCrossBitness = bCrossBitness != FALSE;

	g_pImports->CloseHandle( pProbe->m_hProcess );
	pProbe->m_hProcess = g_pImports->OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, unPid );
	if ( !pProbe->m_hProcess )
	{
		pProbe->m_eFlags |= process::ECaptureFlags::ReopenFailed;
		pProbe->m_unLastError = g_pImports->GetLastError();
		return EScanStatus::ProcessReopenFailed;
	}

	pProbe->m_eFlags |= process::ECaptureFlags::Reopened;
	if ( pProbe->m_bCrossBitness )
	{
		pProbe->m_eFlags |= process::ECaptureFlags::Cross64;
		return WalkProcess64( pProbe, unPid, eFlags );
	}

	nt::ProcessBasicInformation32_t basicInfo;
	ULONG cubReturned = 0;
	g_pImports->NtQueryInformationProcess( pProbe->m_hProcess, ProcessBasicInformation, &basicInfo, sizeof( basicInfo ),
	                                       &cubReturned );
	if ( cubReturned != sizeof( basicInfo ) )
		return EScanStatus::BasicInfoFailed;

	pProbe->m_eFlags |= process::ECaptureFlags::BasicInfo;
	pProbe->m_unParentPid = basicInfo.m_ulInheritedFromUniqueProcessId;

	if ( !basicInfo.m_ulPebBaseAddress )
	{
		wchar_t rgwchImageName[MAX_PATH];
		rgwchImageName[ARRAYSIZE( rgwchImageName ) - 1] = 0;
		cubReturned = iLoadOrder;
		g_pImports->NtQueryInformationProcess( pProbe->m_hProcess, ProcessImageFileName, rgwchImageName,
		                                       sizeof( rgwchImageName ), &cubReturned );
		if ( cubReturned )
			CopyWideFill( pProbe->m_wszImagePath, rgwchImageName + sizeof( UNICODE_STRING ) / sizeof( wchar_t ),
			              ARRAYSIZE( pProbe->m_wszImagePath ) );
		return EScanStatus::NoPeb;
	}

	pProbe->m_eFlags |= process::ECaptureFlags::PebAddress;

	SIZE_T cubRead = 0;
	g_pImports->ReadProcessMemory( pProbe->m_hProcess,
	                               reinterpret_cast<const void *>( static_cast<uptr>( basicInfo.m_ulPebBaseAddress ) ),
	                               &pProbe->m_Peb, sizeof( nt::Peb32_t ), &cubRead );
	if ( cubRead != sizeof( nt::Peb32_t ) )
		return EScanStatus::PebReadFailed;
	pProbe->m_eFlags |= process::ECaptureFlags::PebRead;

	if ( HasFlag( eFlags, EProbeFlags::Parameters ) )
	{
		g_pImports->ReadProcessMemory(
		    pProbe->m_hProcess,
		    reinterpret_cast<const void *>( static_cast<uptr>( pProbe->m_Peb.m_ulProcessParameters ) ),
		    &pProbe->m_ProcessParameters, nt::Arch32_t::k_cubProcessParametersSnapshot, &cubRead );
		if ( cubRead != nt::Arch32_t::k_cubProcessParametersSnapshot )
			return EScanStatus::ProcessReadFailed;

		bool bOk = true;
		CopyNameToProbe32( pProbe, pProbe->m_ProcessParameters.m_CurrentDirectoryPath, pProbe->m_wszCurrentDirectory,
		                   ARRAYSIZE( pProbe->m_wszCurrentDirectory ), &bOk );
		if ( !bOk )
			return EScanStatus::ProcessReadFailed;
		CopyNameToProbe32( pProbe, pProbe->m_ProcessParameters.m_ImagePathName, pProbe->m_wszImagePath,
		                   ARRAYSIZE( pProbe->m_wszImagePath ), &bOk );
		if ( !bOk )
			return EScanStatus::ProcessReadFailed;
		CopyNameToProbe32( pProbe, pProbe->m_ProcessParameters.m_CommandLine, pProbe->m_wszCommandLine,
		                   ARRAYSIZE( pProbe->m_wszCommandLine ), &bOk );
		if ( !bOk )
			return EScanStatus::ProcessReadFailed;
	}

	u8 rgubLdr[nt::Arch32_t::k_cubPebLdrSnapshot];
	g_pImports->ReadProcessMemory( pProbe->m_hProcess,
	                               reinterpret_cast<const void *>( static_cast<uptr>( pProbe->m_Peb.m_ulLdr ) ),
	                               rgubLdr, sizeof( rgubLdr ), &cubRead );
	if ( cubRead != sizeof( rgubLdr ) )
	{
		pProbe->m_eFlags |= process::ECaptureFlags::LdrReadFailed;
		return EScanStatus::ProcessReadFailed;
	}
	pProbe->m_eFlags |= process::ECaptureFlags::LdrRead;

	if ( HasFlag( eFlags, EProbeFlags::Modules ) )
	{
		const auto &ldr = *reinterpret_cast<const nt::PebLdrData32_t *>( rgubLdr );

		nt::LdrDataTableEntry32_t entry;
		entry.m_InLoadOrderLinks.m_ulFlink = ldr.m_InLoadOrderModuleList.m_ulFlink;
		entry.m_InInitializationOrderLinks.m_ulFlink = ldr.m_InInitializationOrderModuleList.m_ulFlink;
		entry.m_InMemoryOrderLinks.m_ulFlink = ldr.m_InMemoryOrderModuleList.m_ulFlink;

		u32 unFirstEntry = ldr.m_InLoadOrderModuleList.m_ulFlink;
		if ( !HasFlag( eFlags, EProbeFlags::LoadOrder ) )
		{
			unFirstEntry = HasFlag( eFlags, EProbeFlags::InitOrder ) ? ldr.m_InInitializationOrderModuleList.m_ulFlink
			                                                         : ldr.m_InMemoryOrderModuleList.m_ulFlink;
		}

		if ( !ReadNextLdrEntry( pProbe, 0, &entry, eFlags ) )
		{
			pProbe->m_eFlags |= process::ECaptureFlags::FirstEntryFailed;
			return EScanStatus::ProcessReadFailed;
		}
		pProbe->m_eFlags |= process::ECaptureFlags::FirstEntry;

		i32 cLeft = k_cMaxModules;
		for ( ;; )
		{
			--cLeft;

			ProbeModule_t module;
			memset( &module, 0, sizeof( module ) );
			const u32 cubName = entry.m_FullDllName.m_cubLength;
			module.m_ulBase = static_cast<u64>( static_cast<i64>( static_cast<i32>( entry.m_ulDllBase ) ) );
			module.m_iLoadOrder = iLoadOrder++;
			module.m_cubImage = 0x1000;
			if ( cubName >= k_cubPeb64Name )
			{
				pProbe->m_eFlags |= process::ECaptureFlags::NameTooLong;
			}
			else
			{
				wchar_t rgwchName[MAX_PATH];
				cubRead = 0;
				g_pImports->ReadProcessMemory(
				    pProbe->m_hProcess,
				    reinterpret_cast<const void *>( static_cast<uptr>( entry.m_FullDllName.m_ulBuffer ) ), rgwchName,
				    cubName, &cubRead );
				if ( cubRead == cubName )
				{
					rgwchName[cubName >> 1] = 0;
					CopyWideFill( module.m_wszFullName, rgwchName, ARRAYSIZE( module.m_wszFullName ) );
					const wchar_t *pwszBaseName = util::wstr::BaseName( module.m_wszFullName );
					if ( pwszBaseName )
						CopyWideFill( module.m_wszBaseName, pwszBaseName, ARRAYSIZE( module.m_wszBaseName ) );
				}
				else
				{
					pProbe->m_eFlags |= process::ECaptureFlags::NameReadFailed;
				}
			}
			AppendModule( pProbe, module );

			if ( !ReadNextLdrEntry( pProbe, unFirstEntry, &entry, eFlags ) || !entry.m_ulDllBase )
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

} // namespace vac::workers::image_scan
