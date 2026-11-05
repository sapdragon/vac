// @binary: 2023d8c3
#include "internal/types.hpp"
#include "bootstrap/blob.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/module.hpp"
#include "crt/intrinsics.hpp"

namespace vac::workers::driver_inventory
{

// @orig: 8B 44 24 ? B9 ? ? ? ? 39 08 73 ? 6A ? 58 C3 53 56 8B 74 24 ? 57 51 6A ? 56 89 08 E8 ? ? ? ? 8B 4C 24 ? 83 C4 ? 33 DB
int RunDriverInventory( const Input_t &input, DriverInventoryReport_t &report, u32 *pcubOutput ) noexcept
{
	if ( *pcubOutput < sizeof( report ) )
		return static_cast<int>( EWorkerResult::OutputTooSmall );

	*pcubOutput = sizeof( report );
	memset( &report, 0, sizeof( report ) );
	report.m_unMagic = k_unDriverInventoryMagic;
	report.m_unVersion = 1;

	EWorkerResult eResult = EWorkerResult::BootstrapFailed;
	EScanStatus eStatus = EScanStatus::BootstrapFailed;
	if ( bootstrap::BootstrapMain( &input ) )
	{
		eStatus = CollectDriverServiceInventory( report, g_pImports );
		eResult = EWorkerResult::Collected;
	}

	bootstrap::BootstrapTeardown();
	report.m_eStatus = eStatus;
	return static_cast<int>( eResult );
}

// @orig: 8B 44 24 ? B9 ? ? ? ? 39 08 73 ? 6A ? 58 C3 53 56 8B 74 24 ? 57 51 6A ? 56 89 08 E8 ? ? ? ? 8B 4C 24 ? 83 C4 ? 83 66
int RunServiceImageDigest( const Input_t &input, ServiceDigestReport_t &report, u32 *pcubOutput ) noexcept
{
	if ( *pcubOutput < sizeof( report ) )
		return static_cast<int>( EWorkerResult::OutputTooSmall );

	*pcubOutput = sizeof( report );
	memset( &report, 0, sizeof( report ) );
	report.m_unVersion = 0;
	report.m_unMagic = k_unServiceDigestMagic;

	EWorkerResult eResult = EWorkerResult::BootstrapFailed;
	EScanStatus eStatus = EScanStatus::BootstrapFailed;
	if ( bootstrap::BootstrapMain( &input ) )
	{
		eStatus = CollectServiceImageDigests( report, g_pImports );
		eResult = EWorkerResult::Collected;
	}

	bootstrap::BootstrapTeardown();
	report.m_eStatus = eStatus;
	return static_cast<int>( eResult );
}

} // namespace vac::workers::driver_inventory

#include "internal/module_data.inl"

VAC_WORKER( vac::workers::driver_inventory::RunDriverInventory, vac::workers::driver_inventory::k_unDriverInventoryId,
            1, 0xF8, 0xA1, 0x7D, 0x1A, 0x97, 0xCE, 0x21, 0xFA, 0xC3, 0x71, 0x14, 0xD7, 0xEF, 0xF2, 0x00, 0x69, 0x08,
            0x0D, 0x43, 0xF6, 0xE4, 0x95, 0xFB, 0x5A, 0xF7, 0x63, 0x93, 0x22, 0x2E, 0xB5, 0x0B, 0x1C );

VAC_WORKER( vac::workers::driver_inventory::RunServiceImageDigest, vac::workers::driver_inventory::k_unServiceDigestId,
            1, 0xC9, 0x0D, 0x98, 0xE7, 0x48, 0x28, 0x9C, 0xF6, 0x7B, 0xEB, 0xEF, 0xF3, 0x30, 0x12, 0x35, 0x5E, 0xD5,
            0x82, 0x27, 0x44, 0x0D, 0x1A, 0xF0, 0xB7, 0xB6, 0x18, 0x7A, 0x16, 0xE8, 0x78, 0x78, 0x25 );
