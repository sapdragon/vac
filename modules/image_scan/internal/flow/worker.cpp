// @binary: 33211402
#include "../scanner.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/scan_status.hpp"
#include "crt/intrinsics.hpp"
#include "file/file.hpp"
#include "process/process.hpp"
#include "util/encoding.hpp"

namespace vac::workers::image_scan
{

namespace
{

// @orig: 55 8B EC 83 E4 ? B8 ? ? ? ? E8 ? ? ? ? 56
EScanStatus ScanModuleFileOrMemory( ScanSession_t *pSession, const wchar_t *pwszPath, u64 ulModuleBase,
                                    ModuleReport_t *pModule, PatternReport_t *pPatterns,
                                    PeHeadersReport_t *pPeHeaders ) noexcept
{
	ScannerContext_t ctx;
	InitScannerContext( &ctx );
	memset( pModule, 0, sizeof( *pModule ) );

	EScanStatus eStatus;
	if ( pwszPath )
	{
		if ( FindModuleByPath( pSession->m_pProbe, pwszPath ) )
			pModule->m_bListedInProcess = 1;

		CleanupScannerContext( &ctx );
		if ( OpenFilePath( &ctx, pwszPath ) )
		{
			eStatus = DeepPeScan( &ctx );
			if ( eStatus == EScanStatus::Ok )
			{
				DumpModuleInfo( &ctx, pModule );
				if ( pPeHeaders )
					DumpPeHeaders( &ctx, pPeHeaders );
			}
			HashStreamAndScanPatterns( &ctx, file::GetFileSizeOrZero( g_pImports, ctx.m_hFile ), pModule, pPatterns );
			CleanupScannerContext( &ctx );
		}
		else
		{
			eStatus = EScanStatus::OpenFailed;
		}
	}
	else
	{
		RegionWalk_t walk;
		memset( &walk, 0, sizeof( walk ) );
		walk.m_ulNext = ulModuleBase;
		WalkProcessRegion( pSession->m_pProbe->m_hProcess, &walk );

		pModule->m_cRegions = static_cast<u8>( walk.m_cRegions );
		u32 cubMapped = static_cast<u32>( walk.m_cubContiguous );
		pModule->m_cubContiguous = cubMapped;
		pModule->m_unFirstProtect = walk.m_First.Protect;
		pModule->m_unProtectMask = walk.m_unProtectMask;

		u64 ulImage = walk.m_ulFirstCommitted;
		if ( !ulImage )
		{
			ulImage = ulModuleBase;
			cubMapped = 0x1000;
		}

		if ( FindModuleByAddress( pSession->m_pProbe, ulImage ) )
			pModule->m_bListedInProcess = 1;

		eStatus = SetMemoryMapping( &ctx, ulImage, cubMapped, pSession->m_pProbe->m_hProcess );
		if ( eStatus == EScanStatus::Ok )
		{
			eStatus = ParsePeHeader( &ctx );
			if ( eStatus == EScanStatus::Ok )
			{
				pModule->m_cubImage =
				    ctx.m_bPe64 ? ctx.m_OptionalHeader64.SizeOfImage : ctx.m_OptionalHeader32.SizeOfImage;
				DumpModuleInfo( &ctx, pModule );
				if ( pPeHeaders )
					DumpPeHeaders( &ctx, pPeHeaders );
			}
			CleanupScannerContext( &ctx );

			// @note / sapdragon: this overwrites a parse failure with the mapping's zero. the report says ok, keep it
			if ( walk.m_First.BaseAddress )
			{
				const u32 cubRegion = static_cast<u32>( walk.m_First.RegionSize );
				eStatus = SetMemoryMapping( &ctx, walk.m_First.BaseAddress, cubRegion, pSession->m_pProbe->m_hProcess );
				if ( eStatus == EScanStatus::Ok )
					HashStreamAndScanPatterns( &ctx, cubRegion, pModule, pPatterns );
			}
			CleanupScannerContext( &ctx );
		}
	}

	pModule->m_eStatus = eStatus;
	CleanupScannerContext( &ctx );
	CloseReader( &ctx );
	return eStatus;
}

} // namespace

// @orig: 8B 54 24 ? 8B C2
EProbeFlags *PermuteScanAccessFlags( EProbeFlags *peFlags, EScanAccess eAccess ) noexcept
{
	const u32 unAccess = static_cast<u32>( eAccess );
	*peFlags = static_cast<EProbeFlags>(
	    static_cast<u8>( ( ( unAccess & 0x10 ) != 0 ) | ( ( ( unAccess & 0x40 ) != 0 ) << 1 ) |
	                     ( ( ( unAccess & 0x20 ) != 0 ) << 2 ) | ( ( ( unAccess & 0x80 ) != 0 ) << 3 ) |
	                     ( ( ( unAccess & 0x100 ) != 0 ) << 4 ) | ( ( ( unAccess & 0x200 ) != 0 ) << 5 ) |
	                     ( ( ( unAccess & 0x400 ) != 0 ) << 6 ) | ( ( unAccess >> 11 ) << 7 ) ) );
	return peFlags;
}

// @orig: 55 8B EC 83 E4 ? B8 ? ? ? ? E8 ? ? ? ? 8B 45 ? 53
int RunImageScan( const Input_t &input, Report_t &report, u32 *pcubOutput ) noexcept
{
	if ( *pcubOutput < sizeof( Report_t ) )
		return 4;

	*pcubOutput = k_cubReport;
	memset( &report, 0, k_cubReport );
	memset( &report, 0, sizeof( Report_t ) );

	if ( !bootstrap::BootstrapMain( &input ) )
	{
		report.m_eStatus = EScanStatus::BootstrapFailed;
		return 0;
	}

	report.m_unReportVersion = 5;
	memset( report.m_Patterns.m_rgunPatternBits, 0, sizeof( report.m_Patterns.m_rgunPatternBits ) );
	report.m_Patterns.m_cubText = 0;

	if ( !input.m_unPid && !input.m_unFlags )
	{
		const u64 ulFileId = input.m_ulTarget;

		ScannerContext_t ctx;
		InitScannerContext( &ctx );

		u32 unLastError = 0;
		const EScanStatus eOpenStatus = OpenFileById( &ctx, input.m_unVolumeSerial, ulFileId, &unLastError );
		report.m_eStatus = eOpenStatus;
		report.m_unLastError = unLastError;
		report.m_Primary.m_eStatus = eOpenStatus;
		if ( eOpenStatus == EScanStatus::Ok )
		{
			const EScanStatus eScanStatus = DeepPeScan( &ctx );
			report.m_eStatus = eScanStatus;
			report.m_Primary.m_eStatus = eScanStatus;
			if ( eScanStatus == EScanStatus::Ok )
			{
				DumpModuleInfo( &ctx, &report.m_Primary );
				DumpPeHeaders( &ctx, &report.m_PeHeaders );
			}
			HashStreamAndScanPatterns( &ctx, file::GetFileSizeOrZero( g_pImports, ctx.m_hFile ), &report.m_Primary,
			                           &report.m_Patterns );
		}

		report.m_unVolumeSerial = input.m_unVolumeSerial;
		report.m_ulFileIndex = ulFileId;
		CleanupScannerContext( &ctx );
		CloseReader( &ctx );
	}
	else
	{
		report.m_unPid = input.m_unPid;

		ProcessProbe_t probe;
		InitProbe( &probe );
		process::EnableSeDebugPrivilege( g_pImports );

		EProbeFlags ePermuted;
		const EProbeFlags eFlags = *PermuteScanAccessFlags( &ePermuted, EScanAccess::Modules );
		report.m_eStatus = WalkProcess( &probe, report.m_unPid, eFlags );
		report.m_unLastError = g_pImports->GetLastError();

		if ( report.m_eStatus == EScanStatus::Ok )
		{
			if ( probe.m_bCrossBitness )
				report.m_bFsRedirectionDisabled = DisableWow64FsRedirection();

			PeHeadersReport_t *pPeHeaders = &report.m_PeHeaders;
			report.m_ulCreationTime = probe.m_ulCreationTime;

			ScanSession_t session;
			session.m_pProbe = &probe;
			session.m_rgunUnused[0] = 0;
			session.m_pvScratch = nullptr;

			wchar_t wszPath[MAX_PATH];
			wszPath[0] = 0;
			report.m_szMappedPath[0] = 0;

			u64 ulTarget = input.m_ulTarget;
			if ( !ulTarget )
			{
				DWORD cPathChars = ARRAYSIZE( wszPath );
				if ( g_pImports->QueryFullProcessImageNameW )
					g_pImports->QueryFullProcessImageNameW( probe.m_hProcess, 0, wszPath, &cPathChars );
				if ( !wszPath[0] )
					g_pImports->GetProcessImageFileNameW( probe.m_hProcess, wszPath, ARRAYSIZE( wszPath ) );
				DevicePathToDos( wszPath );

				// @note / sapdragon: only the low half of the base survives, even for a 64-bit target
				const ProbeModule_t *pModule = FindModuleByPath( &probe, wszPath );
				if ( pModule && pModule->m_ulBase )
					ulTarget = static_cast<u32>( pModule->m_ulBase );
			}
			else if ( probe.m_bCrossBitness )
			{
				const ProbeModule_t *pModule = FindModuleByAddress( &probe, ulTarget );
				if ( pModule )
				{
					memcpy( wszPath, pModule->m_wszFullName, sizeof( pModule->m_wszFullName ) );
					DevicePathToDos( wszPath );
				}
			}
			else if ( g_pImports->GetMappedFileNameW &&
			          g_pImports->GetMappedFileNameW( probe.m_hProcess,
			                                          reinterpret_cast<void *>( static_cast<uptr>( ulTarget ) ),
			                                          wszPath, ARRAYSIZE( wszPath ) ) )
			{
				DevicePathToDos( wszPath );
			}

			if ( wszPath[0] )
			{
				util::encoding::WideToUtf8Bounded( g_pImports, wszPath, report.m_szMappedPath,
				                                   sizeof( report.m_szMappedPath ) );
				ScanModuleFileOrMemory( &session, wszPath, ulTarget, &report.m_Primary, &report.m_Patterns,
				                        pPeHeaders );

				pPeHeaders = nullptr;
				GetFileVolumeAndIndex( wszPath, &report.m_unVolumeSerial, &report.m_ulFileIndex );
			}

			ScanModuleFileOrMemory( &session, nullptr, ulTarget, &report.m_Secondary, &report.m_Patterns, pPeHeaders );
			ReleaseScanSession( &session );
		}

		CleanupProbe( &probe );
	}

	bootstrap::BootstrapTeardown();
	return 0;
}

} // namespace vac::workers::image_scan
