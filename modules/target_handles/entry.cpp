// @binary: 762110ce
#include "internal/types.hpp"
#include "bootstrap/blob.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/module.hpp"
#include "crt/intrinsics.hpp"

namespace vac::workers::target_handles
{

// @orig: 55 8B EC 83 E4 ? 81 EC ? ? ? ? 53
int RunTargetHandles( const Input_t &input, Report_t &report, u32 *pcubOutput ) noexcept
{
	HANDLE hProcess = nullptr;
	u8 *pubHandles = nullptr;

	// @note / sapdragon: incoming capacity is ignored, it always writes the whole report
	memset( &report, 0, k_cubReport );
	*pcubOutput = k_cubReport;
	report.m_unMagic = k_unReportMagic;

	EScanStatus eStatus = EScanStatus::BootstrapFailed;
	if ( bootstrap::BootstrapMain( &input ) )
		eStatus = WatchTargetHandles( input, report, &hProcess, &pubHandles );

	if ( hProcess )
		g_pImports->CloseHandle( hProcess );
	if ( pubHandles )
		g_pImports->VirtualFree( pubHandles, 0, MEM_RELEASE );

	bootstrap::BootstrapTeardown();

	report.m_eStatus = eStatus;
	return 0;
}

} // namespace vac::workers::target_handles

#include "internal/module_data.inl"

VAC_WORKER( vac::workers::target_handles::RunTargetHandles, vac::workers::target_handles::k_unModuleId, 1, 0xF0, 0x2D,
            0x57, 0x63, 0xE6, 0xE0, 0x41, 0x99, 0xC3, 0xC6, 0xAF, 0x22, 0x06, 0xD8, 0xA0, 0xF0, 0xFA, 0xCE, 0xAF, 0xD2,
            0x33, 0xDD, 0x9E, 0x16, 0x88, 0xAE, 0x9E, 0xB3, 0xAF, 0x7D, 0x74, 0xC7 );
