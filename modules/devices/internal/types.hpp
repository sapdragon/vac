#pragma once

#include "bootstrap/imports.hpp"
#include "core/enum.hpp"
#include "core/layout.hpp"
#include "core/packets.hpp"
#include "core/scan_status.hpp"

namespace vac::workers::devices
{

inline constexpr u32 k_unModuleId = 0x05EC50DC;
inline constexpr u32 k_unReportMagic = 0x93FFB624;
inline constexpr u32 k_cubPropertyBuffer = 2048;
inline constexpr u32 k_cubPropertyLimit = 1024;

enum class EDeviceKind : u32
{
	Pci = 1,
	Usb = 2,
};

enum class EReportFlags : u32
{
	NoSuchDevInst = 1,
};
VAC_FLAGS( EReportFlags )

#pragma pack( push, 1 )
struct Input_t
{
	u8 m_rgubBootstrap[8];
	u8 m_rgubReserved[152];
};

struct DeviceEntry_t
{
	u32 m_unKindAndClass;
	u16 m_unVendorId;
	u16 m_unDeviceId;
};

struct Report_t
{
	u8 m_rgubDispatcher[16];
	u32 m_unMagic;
	EScanStatus m_eStatus;
	u32 m_cDevices;
	EReportFlags m_eFlags;
	DeviceEntry_t m_rgDevices[0x1FC];
};
#pragma pack( pop )
VAC_LAYOUT_SIZE( Input_t, k_cubEncryptedConfig );
VAC_LAYOUT_SIZE( DeviceEntry_t, 8 );
VAC_LAYOUT( Report_t, m_unMagic, 0x10 );
VAC_LAYOUT( Report_t, m_eStatus, 0x14 );
VAC_LAYOUT( Report_t, m_cDevices, 0x18 );
VAC_LAYOUT( Report_t, m_eFlags, 0x1C );
VAC_LAYOUT( Report_t, m_rgDevices, 0x20 );
VAC_LAYOUT_SIZE( Report_t, k_cubReport );

int ParseHex( const char *pszText, u32 cDigits, u32 *punValue ) noexcept;
char *FindString( char *pszHaystack, const char *pszNeedle ) noexcept;

} // namespace vac::workers::devices
