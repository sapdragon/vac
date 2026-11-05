// @binary: 2794a04
#include "internal/types.hpp"
#include "bootstrap/blob.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/module.hpp"
#include "crt/intrinsics.hpp"

namespace vac::workers::shared_section
{

// @orig: 81 EC ? ? ? ? 53
int RunSharedSection( const Input_t &input, Report_t &report, u32 *pcubOutput ) noexcept
{
	// @note / sapdragon: incoming capacity is ignored, it always writes the whole report
	memset( &report, 0, k_cubReport );
	*pcubOutput = k_cubReport;
	report.m_unMagic = k_unReportMagic;

	if ( !bootstrap::BootstrapMain( &input ) )
		report.m_eStatus = EScanStatus::BootstrapFailed;
	else
		ReadMapping( input, report, g_pImports );

	bootstrap::BootstrapTeardown();
	return 0;
}

} // namespace vac::workers::shared_section

#include "internal/module_data.inl"

VAC_WORKER( vac::workers::shared_section::RunSharedSection, vac::workers::shared_section::k_unModuleId, 1, 0x59, 0xC0,
            0x01, 0x01, 0xE1, 0x91, 0x50, 0x6B, 0xDE, 0x54, 0xAB, 0x5B, 0xCF, 0x38, 0x9E, 0x93, 0xE0, 0x2E, 0x73, 0x74,
            0x71, 0x01, 0x3F, 0x9C, 0xC2, 0x55, 0x22, 0x1D, 0x70, 0x8A, 0xC5, 0x33 );
