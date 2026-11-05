// @binary: 1da8fb5c
#include "internal/types.hpp"
#include "bootstrap/blob.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/module.hpp"
#include "crt/intrinsics.hpp"

namespace vac::workers::system_handles
{

// @orig: 55 8B EC 83 E4 ? B8
int RunSystemHandles( const Input_t &input, Report_t &report, u32 *pcubOutput ) noexcept
{
	if ( *pcubOutput < k_cubReport )
		return 4;
	*pcubOutput = k_cubReport;

	memset( &report, 0, k_cubReport );
	memset( &report, 0, k_cubReport );

	if ( !bootstrap::BootstrapMain( &input ) )
	{
		report.m_eStatus = EScanStatus::BootstrapFailed;
		return 0;
	}

	report.m_unReportType = 3;
	report.m_unPackedVersion = g_pSession->m_unPackedVersion;

	ScanContext_t context;
	ConstructStringTable( context.m_Directories );
	ConstructStringTable( context.m_BaseNames );
	context.m_unMinPid = input.m_unMinPid;
	context.m_unMaxPid = input.m_unMaxPid;
	context.m_bIncludeExited = HasFlag( input.m_eFlags, EInputFlags::IncludeExited );
	context.m_bFilterByAge = HasFlag( input.m_eFlags, EInputFlags::FilterByAge );
	context.m_bLimitStrings = HasFlag( input.m_eFlags, EInputFlags::LimitStrings );
	context.m_DirectoryHashes = {};
	context.m_BaseNameHashes = {};
	context.m_pReport = &report;
	context.m_cSnapshot = 0;
	context.m_unMaxAgeSeconds = input.m_unMaxAgeSeconds;

	CollectReport( context, report );

	// @note / sapdragon: only on this path, a failed bootstrap returns without it. the frees after it go through the real IAT
	bootstrap::BootstrapTeardown();

	if ( context.m_BaseNameHashes.m_punHashes )
		FreeMemory( context.m_BaseNameHashes.m_punHashes );
	if ( context.m_DirectoryHashes.m_punHashes )
		FreeMemory( context.m_DirectoryHashes.m_punHashes );
	DestructStringTable( context.m_BaseNames );
	DestructStringTable( context.m_Directories );
	return 0;
}

} // namespace vac::workers::system_handles

#include "internal/module_data.inl"

VAC_WORKER( vac::workers::system_handles::RunSystemHandles, vac::workers::system_handles::k_unModuleId, 1, 0x03, 0x3C,
            0x3B, 0xA0, 0xF6, 0x20, 0x4B, 0x32, 0xAB, 0x3A, 0x3A, 0x4D, 0x6E, 0x71, 0xA0, 0x60, 0xA0, 0x64, 0xE9, 0xBA,
            0x2E, 0xED, 0x9A, 0x84, 0x6B, 0x50, 0xE0, 0x0B, 0x09, 0x9E, 0x32, 0xB6 );
