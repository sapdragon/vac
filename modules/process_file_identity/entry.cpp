// @binary: a8848995
#include "internal/types.hpp"
#include "bootstrap/blob.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/module.hpp"
#include "crt/intrinsics.hpp"
#include "file/file.hpp"
#include "process/process.hpp"
#include "util/encoding.hpp"
#include "util/hashing.hpp"
#include "util/strings.hpp"
#include "util/wstr.hpp"

namespace vac::workers::process_file_identity
{

// @note / sapdragon: no BootstrapTeardown in any of the three workers, this binary never tears down

// @orig: 55 8B EC 83 E4 ? B8 ? ? ? ? E8 ? ? ? ? 8B 45 ? 53 56 57 81 38 ? ? ? ? 73 ? 6A ? 58 E9 ? ? ? ? 8B 7D ? B9 ? ? ? ? 51 33 DB
int RunProcessDetails( const ProcessInput_t &input, ProcessReport_t &report, u32 *pcubOutput ) noexcept
{
	// @note / sapdragon: the capacity each worker asks for. all of them write the whole report anyway
	if ( *pcubOutput < offsetof( ProcessReport_t, m_rgubUnused3 ) )
		return 4;

	*pcubOutput = k_cubReport;
	memset( &report, 0, k_cubReport );
	memset( &report.m_unPid, 0, offsetof( ProcessReport_t, m_unDetailType ) - offsetof( ProcessReport_t, m_unPid ) );

	if ( !bootstrap::BootstrapMain( &input ) )
	{
		report.m_eStatus = EScanStatus::BootstrapFailed;
		return 0;
	}

	process::EnableSeDebugPrivilege( g_pImports );

	wchar_t rgrgwszPaths[3][k_cPathChars];
	for ( auto &wszCandidate : rgrgwszPaths )
		wszCandidate[0] = 0;

	report.m_szImagePath[0] = 0;
	report.m_unFullImageNameError = k_unUnsetError;
	report.m_unImageFileNameError = k_unUnsetError;
	g_pImports->SetLastError( 0 );
	report.m_unPid = input.m_unPid;

	EScanStatus eOpenStatus;
	const HANDLE hProcess = g_pImports->OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, input.m_unPid );
	if ( hProcess == INVALID_HANDLE_VALUE || !hProcess )
	{
		eOpenStatus = EScanStatus::ProcessReopenFailed;
	}
	else
	{
		u32 cPaths = 0;
		if ( g_pImports->QueryFullProcessImageNameW )
		{
			DWORD cChars = k_cPathChars;
			g_pImports->QueryFullProcessImageNameW( hProcess, 0, rgrgwszPaths[0], &cChars );
			if ( cChars - 1 < k_cPathChars - 1 )
			{
				NtDeviceToDosPath( rgrgwszPaths[0] );
				if ( !report.m_szImagePath[0] )
					util::encoding::WideToUtf8Bounded( g_pImports, rgrgwszPaths[0], report.m_szImagePath,
					                                   sizeof( report.m_szImagePath ) );
				cPaths = 1;
			}
			report.m_unFullImageNameError = g_pImports->GetLastError();
		}

		wchar_t *pwszPath = rgrgwszPaths[cPaths];
		if ( g_pImports->GetProcessImageFileNameW( hProcess, pwszPath, k_cPathChars ) - 1 < k_cPathChars - 1 )
		{
			NtDeviceToDosPath( pwszPath );
			if ( !report.m_szImagePath[0] )
				util::encoding::WideToUtf8Bounded( g_pImports, pwszPath, report.m_szImagePath,
				                                   sizeof( report.m_szImagePath ) );
			++cPaths;
		}

		pwszPath = rgrgwszPaths[cPaths];
		report.m_unImageFileNameError = g_pImports->GetLastError();
		if ( GetFirstModulePath( report.m_unPid, pwszPath ) )
		{
			NtDeviceToDosPath( pwszPath );
			if ( !report.m_szImagePath[0] )
				util::encoding::WideToUtf8Bounded( g_pImports, pwszPath, report.m_szImagePath,
				                                   sizeof( report.m_szImagePath ) );
		}

		PeFile_t file;
		for ( const auto &wszCandidate : rgrgwszPaths )
		{
			InitPeFile( file );
			ResetPeFile( file );

			EScanStatus ePeStatus = OpenPeFile( file, wszCandidate );
			if ( ePeStatus == EScanStatus::Ok )
				ePeStatus = ParsePeFile( file );
			report.m_ePeStatus = ePeStatus;

			if ( ePeStatus == EScanStatus::Ok )
			{
				BuildImageFingerprints( file, report.m_Fingerprints );
				report.m_unDetailType = 3;
				BuildImageDetails( file, report.m_Details );
				ExportImageHeaders( file, report.m_Headers );

				const u32 cubStrings = CollectVersionStrings( wszCandidate, report.m_szVersionStrings );
				for ( u32 ib = 0; ib < cubStrings; ++ib )
				{
					if ( !report.m_szVersionStrings[ib] )
						report.m_szVersionStrings[ib] = ' ';
				}
				report.m_szVersionStrings[cubStrings] = 0;

				util::encoding::WideToUtf8Bounded( g_pImports, wszCandidate, report.m_szImagePath,
				                                   sizeof( report.m_szImagePath ) );
				ResetPeFile( file );
				ClosePeFile( file );
				break;
			}

			report.m_unPeError = g_pImports->GetLastError();
			ResetPeFile( file );
			ClosePeFile( file );
		}

		HANDLE hToken = nullptr;
		if ( g_pImports->OpenProcessToken( hProcess, TOKEN_QUERY, &hToken ) )
		{
			DWORD cubInfo = 0;
			void *pInfo = nullptr;
			g_pImports->GetTokenInformation( hToken, TokenSessionId, &report.m_unSessionId,
			                                 sizeof( report.m_unSessionId ), &cubInfo );
			g_pImports->GetTokenInformation( hToken, TokenUser, nullptr, 0, &cubInfo );
			if ( cubInfo )
				pInfo = g_pImports->HeapAlloc( g_pImports->GetProcessHeap(), 0, cubInfo );

			if ( g_pImports->GetTokenInformation( hToken, TokenUser, pInfo, cubInfo, &cubInfo ) )
			{
				char *pszSid = nullptr;
				if ( g_pImports->ConvertSidToStringSidA( static_cast<TOKEN_USER *>( pInfo )->User.Sid, &pszSid ) )
				{
					util::CopyA( report.m_szUserSid, pszSid, sizeof( report.m_szUserSid ) );
					g_pImports->LocalFree( pszSid );
				}
			}

			g_pImports->HeapFree( g_pImports->GetProcessHeap(), 0, pInfo );
			g_pImports->CloseHandle( hToken );
		}

		g_pImports->CloseHandle( hProcess );
		eOpenStatus = EScanStatus::Ok;
	}

	report.m_eStatus = eOpenStatus;
	report.m_eOpenStatus = eOpenStatus;
	report.m_unProbeError = g_pImports->GetLastError();

	ProcessCapture_t capture;
	InitProcessCapture( capture );
	const EScanStatus eProbeStatus =
	    CaptureProcess( capture, report.m_unPid, EncodeCaptureFlags( ECaptureRequest::Parameters ) );
	report.m_eProbeStatus = eProbeStatus;
	report.m_unProbeError = capture.m_unLastError;
	if ( eProbeStatus == EScanStatus::Ok )
	{
		report.m_unParentPid = capture.m_unParentPid;
		util::encoding::WideToUtf8Bounded( g_pImports, capture.m_wszCommandLine, report.m_szCommandLine,
		                                   sizeof( report.m_szCommandLine ) );
		util::encoding::WideToUtf8Bounded( g_pImports, capture.m_wszCurrentDirectory, report.m_szCurrentDirectory,
		                                   sizeof( report.m_szCurrentDirectory ) );
		QueryFileIdentity( capture.m_wszCurrentDirectory, true, &report.m_unCurrentDirectoryVolume,
		                   &report.m_CurrentDirectoryId );
	}

	const u32 unPid = report.m_unPid;
	u32 unParentPid = 0;

	// @note / sapdragon: the snapshot handle is never closed. a leak in the original, keep it
	const HANDLE hSnapshot = g_pImports->CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if ( hSnapshot != INVALID_HANDLE_VALUE )
	{
		PROCESSENTRY32W entry;
		entry.dwSize = sizeof( entry );
		if ( g_pImports->Process32FirstW( hSnapshot, &entry ) )
		{
			do
			{
				if ( unPid == entry.th32ProcessID )
					unParentPid = entry.th32ParentProcessID;
			} while ( g_pImports->Process32NextW( hSnapshot, &entry ) );

			if ( unParentPid )
				report.m_unParentPid = unParentPid;
		}
	}

	FreeProcessCapture( capture );
	return 0;
}

// @orig: 55 8B EC 83 E4 ? B8 ? ? ? ? E8 ? ? ? ? 8B 45 ? 53 56 57 81 38 ? ? ? ? 73 ? 6A ? 58 E9 ? ? ? ? 8B 7D ? B9 ? ? ? ? 51 6A
int RunFileIdentity( FileInput_t &input, FileReport_t &report, u32 *pcubOutput ) noexcept
{
	if ( *pcubOutput < offsetof( FileReport_t, m_rgubUnused2 ) )
		return 4;

	*pcubOutput = k_cubReport;
	memset( &report, 0, k_cubReport );
	memset( &report.m_eOpenStatus, 0,
	        offsetof( FileReport_t, m_rgubUnused2 ) - offsetof( FileReport_t, m_eOpenStatus ) );

	if ( !bootstrap::BootstrapMain( &input ) )
	{
		report.m_eStatus = EScanStatus::BootstrapFailed;
		return 0;
	}

	wchar_t wszPath[k_cPathChars];
	g_pImports->MultiByteToWideChar( CP_UTF8, 0, input.m_szPath, -1, wszPath, k_cPathChars );

	PeFile_t file;
	InitPeFile( file );

	const u32 cchPath = BoundedPathLength( input.m_szPath );
	if ( static_cast<i32>( cchPath ) > 0 )
	{
		util::CopyA( report.m_szPath, input.m_szPath, sizeof( report.m_szPath ) );

		const EScanStatus eOpenStatus = OpenPeFile( file, wszPath );
		report.m_eOpenStatus = eOpenStatus;
		if ( eOpenStatus != EScanStatus::Ok )
		{
			report.m_unOpenError = g_pImports->GetLastError();
		}
		else
		{
			report.m_cubFile = vac::file::GetFileSizeOrZero( g_pImports, file.m_hFile );
			report.m_ePeStatus = ParsePeFile( file );
			ResetPeFile( file );
		}

		if ( !QueryFileIdentity( wszPath, false, &report.m_unVolume, &report.m_FileId ) )
			report.m_unIdentityError = g_pImports->GetLastError();

		// @note / sapdragon: this cuts the utf-8 input but keeps querying the wide copy from above, so every
		// ancestor gets the id of the full path. looks wrong, it is what the original does
		char *const pszStart = input.m_szPath;
		char *pszChar = pszStart + cchPath - 1;
		u32 cAncestors = 0;
		while ( pszChar > pszStart )
		{
			if ( cAncestors > ARRAYSIZE( report.m_rgAncestors ) - 1 )
				break;

			while ( *pszChar != '\\' )
			{
				--pszChar;
				if ( pszChar <= pszStart )
					break;
			}
			if ( pszChar <= pszStart )
				break;

			if ( *pszChar == '\\' )
			{
				u32 unVolume = 0;
				FileId_t fileId{};
				pszChar[1] = 0;
				QueryFileIdentity( wszPath, true, &unVolume, &fileId );
				report.m_rgAncestors[cAncestors] = fileId;
				++cAncestors;
				--pszChar;
			}
		}
	}

	ResetPeFile( file );
	ClosePeFile( file );
	return 0;
}

// @orig: 55 8B EC 83 E4 ? B8 ? ? ? ? E8 ? ? ? ? 8B 45 ? 53 BB
int RunDirectoryInventory( const DirectoryInput_t &input, DirectoryReport_t &report, u32 *pcubOutput ) noexcept
{
	if ( *pcubOutput < sizeof( DirectoryReport_t ) )
		return 4;

	*pcubOutput = k_cubReport;
	memset( &report, 0, k_cubReport );
	memset( &report, 0, k_cubReport );
	report.m_unMagic = k_unDirectoryMagic;
	report.m_unVersion = 2;

	if ( !bootstrap::BootstrapMain( &input ) )
	{
		report.m_eStatus = EScanStatus::BootstrapFailed;
		return 0;
	}

	wchar_t wszPath[MAX_PATH];
	const wchar_t *pwszPath = wszPath;
	const u32 unVolume = input.m_unVolume;
	const FileId_t fileId = input.m_FileId;
	const u32 unIncludeMask = input.m_unIncludeMask;
	const u32 unExcludeMask = input.m_unExcludeMask;
	DWORD cProfileChars = MAX_PATH;
	g_pImports->MultiByteToWideChar( CP_UTF8, 0, input.m_szPath, -1, wszPath, ARRAYSIZE( wszPath ) );
	report.m_eStatus = EScanStatus::Ok;

	wchar_t wszProfile[MAX_PATH];
	if ( !wszPath[0] && !( fileId.m_unHigh | fileId.m_unLow ) && !unVolume )
	{
		ProcessCapture_t capture;
		InitProcessCapture( capture );

		u32 unFoundPid = 0;
		u32 cFound = 0;
		FindProfileProcess( &unFoundPid, &cFound );

		const u32 unProfilePid = cFound == 1 ? unFoundPid : g_pImports->GetCurrentProcessId();
		report.m_unProfilePid = unProfilePid;

		bool bFailedOpen = false;
		const HANDLE hProcess = g_pImports->OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, unProfilePid );
		if ( hProcess == INVALID_HANDLE_VALUE )
		{
			report.m_eStatus = EScanStatus::ProcessReopenFailed;
			bFailedOpen = true;
		}
		else
		{
			// @note / sapdragon: neither this token nor the process handle is ever closed. a leak in the original, keep it
			HANDLE hToken = nullptr;
			wszProfile[0] = 0;
			if ( g_pImports->OpenProcessToken( hProcess, TOKEN_QUERY, &hToken ) )
			{
				if ( g_pImports->GetUserProfileDirectoryW )
				{
					if ( g_pImports->GetUserProfileDirectoryW( hToken, wszProfile, &cProfileChars ) )
					{
						report.m_cProfileChars = cProfileChars;
						pwszPath = cProfileChars - 1 <= MAX_PATH - 2 ? wszProfile : wszPath;
					}
					else
					{
						report.m_eStatus = EScanStatus::TokenFailed;
						report.m_unInfoError = g_pImports->GetLastError();
					}
				}
				else
				{
					// @note / sapdragon: valve reuses the no file code for the missing import
					report.m_eStatus = EScanStatus::NoFile;
				}
			}
			else
			{
				report.m_eStatus = EScanStatus::TokenFailed;
				bFailedOpen = true;
			}
		}

		if ( bFailedOpen )
			report.m_unOpenError = g_pImports->GetLastError();

		if ( wszProfile[0] )
		{
			report.m_unProfileHash =
			    util::hashing::PathHashBytes( reinterpret_cast<const u8 *>( wszProfile ), cProfileChars );

			const wchar_t *pwszName = util::wstr::BaseName( wszProfile );
			if ( pwszName )
			{
				char szName[264];
				util::encoding::WideToUtf8Bounded( g_pImports, pwszName, szName, MAX_PATH );
				report.m_unProfileNameHash =
				    util::hashing::PathHashBytes( reinterpret_cast<const u8 *>( szName ), util::StrLenA( szName ) );
			}
		}

		FreeProcessCapture( capture );
	}

	if ( report.m_eStatus == EScanStatus::Ok )
	{
		report.m_unReserved = 0;

		const u16 unScanStatus =
		    EnumerateDirectory( report, unIncludeMask, unExcludeMask, pwszPath, unVolume, fileId, 0 );
		report.m_unScanStatus = unScanStatus;
		report.m_cSkippedInRoot = report.m_cSkipped;
		if ( unScanStatus )
			report.m_unOpenError = g_pImports->GetLastError();
		else
			ExpandDirectories( report, unIncludeMask, unExcludeMask );
	}

	return 0;
}

} // namespace vac::workers::process_file_identity

#include "internal/module_data.inl"

VAC_WORKER( vac::workers::process_file_identity::RunProcessDetails,
            vac::workers::process_file_identity::k_unProcessModuleId, 1, 0x2D, 0xE0, 0x87, 0xC7, 0x18, 0xCA, 0xEC, 0x39,
            0x86, 0x33, 0x98, 0x81, 0x19, 0xF5, 0x5B, 0x0E, 0x2B, 0x1C, 0xFA, 0xF5, 0xFD, 0x44, 0xF7, 0x2C, 0xDB, 0x0A,
            0xC1, 0x52, 0xAA, 0x6C, 0xA5, 0xB8 );
VAC_WORKER( vac::workers::process_file_identity::RunFileIdentity, vac::workers::process_file_identity::k_unFileModuleId,
            1, 0xAC, 0xDE, 0xCA, 0xFA, 0x38, 0x98, 0x17, 0xBE, 0xD7, 0x1C, 0x43, 0xD4, 0xDA, 0x0E, 0xA5, 0x0E, 0x59,
            0xBD, 0xD6, 0xE9, 0xF2, 0x5C, 0xCD, 0x72, 0xB4, 0xEA, 0x40, 0x1F, 0x09, 0x1F, 0x32, 0x22 );
VAC_WORKER( vac::workers::process_file_identity::RunDirectoryInventory,
            vac::workers::process_file_identity::k_unDirectoryModuleId, 1, 0x12, 0xAD, 0xAA, 0x88, 0x93, 0x57, 0xCD,
            0x10, 0x3D, 0x01, 0x51, 0x49, 0xFB, 0x90, 0xA4, 0x10, 0x8B, 0x7B, 0x47, 0xA2, 0xFA, 0x0D, 0x4B, 0xB0, 0xC2,
            0xA2, 0x16, 0x75, 0x59, 0x6A, 0x70, 0x49 );
