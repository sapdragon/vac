// @binary: 87f12249
#include "internal/types.hpp"
#include "bootstrap/blob.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/module.hpp"
#include "crt/intrinsics.hpp"

namespace vac::workers::service_lookup
{

namespace
{

enum class EWorkerResult : int
{
	Completed = 0,
	BootstrapFailed = 1,
	BadArgs = 4,
};

} // namespace

// @orig: 8B 44 24 ? B9
int RunServiceLookup( const Input_t &input, Report_t &report, u32 *pcubOutput ) noexcept
{
	if ( *pcubOutput < sizeof( report ) )
		return static_cast<int>( EWorkerResult::BadArgs );

	*pcubOutput = sizeof( report );
	memset( &report, 0, sizeof( report ) );
	report.m_unReserved = 0;
	report.m_unMagic = k_unReportMagic;

	EWorkerResult eResult = EWorkerResult::BootstrapFailed;
	EScanStatus eStatus;
	if ( bootstrap::BootstrapMain( &input ) )
	{
		eStatus = ReadServiceInfo( report, input.m_unServiceNameHash );
		eResult = EWorkerResult::Completed;
	}
	else
	{
		eStatus = EScanStatus::BootstrapFailed;
	}

	bootstrap::BootstrapTeardown();
	report.m_eStatus = eStatus;
	return static_cast<int>( eResult );
}

} // namespace vac::workers::service_lookup

#include "internal/module_data.inl"

VAC_WORKER( vac::workers::service_lookup::RunServiceLookup, vac::workers::service_lookup::k_unModuleId, 1, 0xEE, 0xA4,
            0x25, 0x38, 0x9C, 0x87, 0xC5, 0xBB, 0x4D, 0x10, 0xD9, 0x90, 0xB7, 0x6F, 0x56, 0xD2, 0x99, 0x76, 0xDB, 0x49,
            0x00, 0x36, 0x01, 0x19, 0x65, 0x46, 0xCE, 0x8B, 0xB8, 0xFC, 0x81, 0xFF );
