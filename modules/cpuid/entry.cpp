// @binary: f418b1dc
#include "internal/types.hpp"
#include "bootstrap/blob.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/module.hpp"
#include "crt/intrinsics.hpp"

namespace vac::workers::cpuid
{

// @orig: 55 8B 6C 24 ? B8
int RunCpuid( const Input_t &input, Report_t &report, u32 *pcubOutput ) noexcept
{
	if ( *pcubOutput < sizeof( Report_t ) )
		return 4;

	*pcubOutput = sizeof( Report_t );
	memset( &report, 0, sizeof( Report_t ) );
	report.m_unReserved18 = 0;
	report.m_unMagic = k_unReportMagic;

	EScanStatus eStatus;
	int nResult;
	if ( bootstrap::BootstrapMain( &input ) )
	{
		HANDLE hThread = g_pImports->GetCurrentThread();
		const DWORD_PTR ulAffinityPrevious = g_pImports->SetThreadAffinityMask( hThread, 1 );
		eStatus = Collect( report );
		g_pImports->SetThreadAffinityMask( hThread, ulAffinityPrevious );
		nResult = 0;
		*pcubOutput = offsetof( Report_t, m_rgRecords ) + report.m_cRecords * sizeof( CpuidRecord_t );
	}
	else
	{
		eStatus = EScanStatus::BootstrapFailed;
		nResult = 1;
	}

	bootstrap::BootstrapTeardown();
	report.m_eStatus = eStatus;
	return nResult;
}

} // namespace vac::workers::cpuid

#include "internal/module_data.inl"

VAC_WORKER( vac::workers::cpuid::RunCpuid, vac::workers::cpuid::k_unModuleId, 1, 0xCB, 0xED, 0xBD, 0x9D, 0xEC, 0xDB,
            0x45, 0xEF, 0x1E, 0x1C, 0xAE, 0x6F, 0x11, 0xE3, 0xFB, 0x9E, 0x2F, 0xFF, 0xBF, 0x20, 0xC8, 0x2C, 0xF3, 0x60,
            0xC9, 0x98, 0xE6, 0xDE, 0xC6, 0xA9, 0x5F, 0x0E );
