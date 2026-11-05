#pragma once

#include "bootstrap/imports.hpp"
#include "core/enum.hpp"
#include "core/layout.hpp"
#include "core/packets.hpp"
#include "core/scan_status.hpp"

namespace vac::workers::driver_inventory
{

inline constexpr u32 k_unDriverInventoryId = 0x06ACD913;
inline constexpr u32 k_unServiceDigestId = 0x06C2B5BB;

inline constexpr u32 k_unDriverInventoryMagic = 0x2F634026;
inline constexpr u32 k_unServiceDigestMagic = 0x538E7074;

enum class EDriverEntryFlags : u32
{
	Service = 1,
	DriverObject = 2,
};
VAC_FLAGS( EDriverEntryFlags )

enum class EWorkerResult : int
{
	Collected = 0,
	BootstrapFailed = 1,
	OutputTooSmall = 4,
};

#pragma pack( push, 1 )
struct Input_t
{
	u8 m_rgubBootstrap[k_cubEncryptedConfig];
};

struct DriverEntry_t
{
	u32 m_unNameHash;
	i16 m_nNameString;
	i16 m_nPathString;
	EDriverEntryFlags m_eFlags;
};

struct DriverInventoryReport_t
{
	u8 m_rgubDispatcher[16];
	u32 m_unMagic;
	EScanStatus m_eStatus;
	u32 m_cEntries;
	u32 m_unVersion;
	u32 m_cServices;
	u32 m_cDriverObjects;
	union
	{
		DriverEntry_t m_rgEntries[169];

		u8 m_rgubEntriesAndStrings[k_cubReport - 0x28];
	};
};

struct ServiceDigestEntry_t
{
	u32 m_unServiceNameHash;
	union
	{
		u8 m_rgubDigest[16];
		struct
		{
			EScanStatus m_eStatus;
			u32 m_unLastError;
			u32 m_rgunZero[2];
		};
	};
};

struct ServiceDigestReport_t
{
	u8 m_rgubDispatcher[16];
	u32 m_unMagic;
	EScanStatus m_eStatus;
	u32 m_cEntries;
	u32 m_unVersion;
	u32 m_unReserved;
	ServiceDigestEntry_t m_rgEntries[203];
};
#pragma pack( pop )
VAC_LAYOUT_SIZE( Input_t, 160 );
VAC_LAYOUT_SIZE( DriverEntry_t, 12 );
VAC_LAYOUT( DriverEntry_t, m_nNameString, 0x04 );
VAC_LAYOUT( DriverEntry_t, m_nPathString, 0x06 );
VAC_LAYOUT( DriverEntry_t, m_eFlags, 0x08 );
VAC_LAYOUT( DriverInventoryReport_t, m_unMagic, 0x10 );
VAC_LAYOUT( DriverInventoryReport_t, m_eStatus, 0x14 );
VAC_LAYOUT( DriverInventoryReport_t, m_cEntries, 0x18 );
VAC_LAYOUT( DriverInventoryReport_t, m_unVersion, 0x1C );
VAC_LAYOUT( DriverInventoryReport_t, m_cServices, 0x20 );
VAC_LAYOUT( DriverInventoryReport_t, m_cDriverObjects, 0x24 );
VAC_LAYOUT( DriverInventoryReport_t, m_rgEntries, 0x28 );
VAC_LAYOUT_SIZE( DriverInventoryReport_t, k_cubReport );
VAC_LAYOUT_SIZE( ServiceDigestEntry_t, 20 );
VAC_LAYOUT( ServiceDigestEntry_t, m_rgubDigest, 0x04 );
VAC_LAYOUT( ServiceDigestEntry_t, m_eStatus, 0x04 );
VAC_LAYOUT( ServiceDigestEntry_t, m_unLastError, 0x08 );
VAC_LAYOUT( ServiceDigestReport_t, m_unMagic, 0x10 );
VAC_LAYOUT( ServiceDigestReport_t, m_eStatus, 0x14 );
VAC_LAYOUT( ServiceDigestReport_t, m_cEntries, 0x18 );
VAC_LAYOUT( ServiceDigestReport_t, m_unVersion, 0x1C );
VAC_LAYOUT( ServiceDigestReport_t, m_rgEntries, 0x24 );
VAC_LAYOUT_SIZE( ServiceDigestReport_t, k_cubReport );

EScanStatus CollectDriverServiceInventory( DriverInventoryReport_t &report, const SystemImports_t *pImports ) noexcept;
EScanStatus CollectServiceImageDigests( ServiceDigestReport_t &report, const SystemImports_t *pImports ) noexcept;

} // namespace vac::workers::driver_inventory
