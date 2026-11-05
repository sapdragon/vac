#pragma once

#include "../types.hpp"

#include "core/enum.hpp"

namespace vac::workers::image_scan
{

inline constexpr u32 k_unThreadReportMagic = 0x69720927;

enum class EThreadMemoryFlags : u32
{
	MappedName = 0x1000,
	InModule = 0x2000,
};
VAC_FLAGS( EThreadMemoryFlags )

#pragma pack( push, 1 )
struct ThreadRecord_t
{
	u32 m_unThreadId;
	EThreadMemoryFlags m_eMemoryFlags;
	u64 m_ulStartAddress;
};

struct ThreadReport_t
{
	u8 m_rgubDispatcher[16];
	u32 m_unMagic;
	EScanStatus m_eStatus;
	u32 m_unReserved;
	u32 m_unLastError;
	u32 m_unPid;
	u32 m_cModules;
	process::ECaptureFlags m_eFlags;
	u32 m_cRecords;
	ThreadRecord_t m_rgRecords[253];
};
#pragma pack( pop )
VAC_LAYOUT_SIZE( ThreadRecord_t, 16 );
VAC_LAYOUT( ThreadReport_t, m_unMagic, 0x10 );
VAC_LAYOUT( ThreadReport_t, m_eStatus, 0x14 );
VAC_LAYOUT( ThreadReport_t, m_unLastError, 0x1C );
VAC_LAYOUT( ThreadReport_t, m_unPid, 0x20 );
VAC_LAYOUT( ThreadReport_t, m_cModules, 0x24 );
VAC_LAYOUT( ThreadReport_t, m_eFlags, 0x28 );
VAC_LAYOUT( ThreadReport_t, m_cRecords, 0x2C );
VAC_LAYOUT( ThreadReport_t, m_rgRecords, 0x30 );
VAC_LAYOUT_SIZE( ThreadReport_t, k_cubReport );

int RunThreadReport( const Input_t &input, ThreadReport_t &report, u32 *pcubOutput ) noexcept;

} // namespace vac::workers::image_scan
