// @binary: 8d88e017
#include "internal/process_context.hpp"
#include "internal/report_builder.hpp"
#include "internal/types.hpp"
#include "bootstrap/blob.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/module.hpp"
#include "crt/intrinsics.hpp"

namespace vac::workers::process_memory_map
{

// @orig: 55 8B EC 83 E4 ? B8 ? ? ? ? E8 ? ? ? ? 8B 45
int RunProcessMemoryMap( const Input_t &input, Report_t &report, u32 *pcubOutput ) noexcept
{
	if ( *pcubOutput < sizeof( Report_t ) )
		return 4;

	*pcubOutput = sizeof( Report_t );
	memset( &report, 0, sizeof( Report_t ) );
	memset( &report, 0, sizeof( Report_t ) );

	if ( bootstrap::BootstrapMain( &input ) )
	{
		report.m_unPid = input.m_unPid;
		report.m_unScanType = 5;

		ProcessContext_t context;
		memset( &context, 0, sizeof( context ) );
		context.m_hProcess = INVALID_HANDLE_VALUE;

		const EScanStatus eStatus = OpenProcessAndCaptureLdr( context, report.m_unPid, g_pImports, g_pSession );
		report.m_unLastError = context.m_unLastError;
		report.m_eCaptureFlags = context.m_eCaptureFlags;
		report.m_eStatus = eStatus;
		report.m_eFlags = ( context.m_bSelfWow64 ? EReportFlags::SelfWow64 : EReportFlags::None ) |
		                  ( report.m_eFlags & static_cast<EReportFlags>( 0xFFFC ) ) |
		                  ( context.m_bCross64 ? EReportFlags::Cross64 : EReportFlags::None );
		if ( eStatus == EScanStatus::Ok )
		{
			report.m_ulCreateTime = context.m_ulCreateTime;
			report.m_cRecords = 0;
			report.m_cubStrings = 0;
			report.m_eStatus = ScanProcess( context, report, input.m_unScanStart, input.m_nMaxHashes,
			                                input.m_nTrimRatio, input.m_unMinHashBase, g_pImports );
		}

		ReleaseProcessContext( context, g_pImports );
		bootstrap::BootstrapTeardown();
	}
	else
	{
		report.m_eStatus = EScanStatus::BootstrapFailed;
	}
	return 0;
}

} // namespace vac::workers::process_memory_map

#include "internal/module_data.inl"

VAC_WORKER( vac::workers::process_memory_map::RunProcessMemoryMap, vac::workers::process_memory_map::k_unModuleId, 1,
            0x38, 0x05, 0x74, 0x3E, 0x04, 0xD7, 0xBB, 0x81, 0xA5, 0x82, 0xBE, 0x8C, 0x91, 0x6F, 0xDB, 0x94, 0x60, 0x15,
            0x6E, 0x3F, 0x1E, 0x07, 0xD7, 0x6A, 0xEF, 0xAD, 0x90, 0x51, 0x48, 0x2E, 0x4A, 0x81 );
