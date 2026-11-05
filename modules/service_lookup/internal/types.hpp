#pragma once

#include "bootstrap/imports.hpp"
#include "core/layout.hpp"
#include "core/packets.hpp"
#include "core/scan_status.hpp"

namespace vac::workers::service_lookup
{

inline constexpr u32 k_unModuleId = 0x0FA94991;
inline constexpr u32 k_unReportMagic = 0x6E1CA4EA;

#pragma pack( push, 1 )
struct Input_t
{
	u8 m_rgubBootstrap[0x64];
	u32 m_unServiceNameHash;
	u8 m_rgubReserved[0x38];
};

struct Report_t
{
	u8 m_rgubDispatcher[16];
	u32 m_unMagic;
	EScanStatus m_eStatus;
	u32 m_unReserved;
	char m_szServiceName[256];
	char m_szDisplayName[256];
	u32 m_unServiceType;
	u32 m_unStartType;
	u32 m_unErrorControl;
	char m_szBinaryPath[256];
	char m_szLoadOrderGroup[32];
	char m_szDependencies[256];
	char m_szServiceStartName[32];
	u32 m_unFileIndexLow;
	u32 m_unFileIndexHigh;
	u32 m_unVolumeSerial;
	u8 m_rgubUnused[k_cubReport - 0x474];
};
#pragma pack( pop )
VAC_LAYOUT_SIZE( Input_t, 160 );
VAC_LAYOUT( Input_t, m_unServiceNameHash, 0x64 );
VAC_LAYOUT( Report_t, m_unMagic, 0x10 );
VAC_LAYOUT( Report_t, m_eStatus, 0x14 );
VAC_LAYOUT( Report_t, m_unReserved, 0x18 );
VAC_LAYOUT( Report_t, m_szServiceName, 0x1C );
VAC_LAYOUT( Report_t, m_szDisplayName, 0x11C );
VAC_LAYOUT( Report_t, m_unServiceType, 0x21C );
VAC_LAYOUT( Report_t, m_szBinaryPath, 0x228 );
VAC_LAYOUT( Report_t, m_szLoadOrderGroup, 0x328 );
VAC_LAYOUT( Report_t, m_szDependencies, 0x348 );
VAC_LAYOUT( Report_t, m_szServiceStartName, 0x448 );
VAC_LAYOUT( Report_t, m_unFileIndexLow, 0x468 );
VAC_LAYOUT( Report_t, m_unFileIndexHigh, 0x46C );
VAC_LAYOUT( Report_t, m_unVolumeSerial, 0x470 );
VAC_LAYOUT_SIZE( Report_t, k_cubReport );

EScanStatus ReadServiceInfo( Report_t &report, u32 unServiceNameHash ) noexcept;

} // namespace vac::workers::service_lookup
