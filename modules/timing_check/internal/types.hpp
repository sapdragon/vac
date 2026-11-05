#pragma once

#include "bootstrap/imports.hpp"
#include "core/layout.hpp"
#include "core/packets.hpp"

namespace vac::workers::timing_check
{

inline constexpr u32 k_unModuleId = 0x0D8C40E1;
inline constexpr u32 k_unReportMagic = 0x34E663C0;

#pragma pack( push, 1 )
struct Input_t
{
	u8 m_rgubUnused0[0x64];
	u32 m_unStubValue;
	u8 m_rgubUnused1[0x38];
};

struct Report_t
{
	u8 m_rgubDispatcher[16];
	u32 m_unMagic;
	u32 m_unTimingCheck;
	u32 m_unBeingDebugged;
	u32 m_unReserved1C;
};

// mov eax, imm32; ret
struct Stub_t
{
	u8 m_ubMovEax;
	u32 m_unImmediate;
	u8 m_ubRet;
};
#pragma pack( pop )
VAC_LAYOUT_SIZE( Input_t, k_cubEncryptedConfig );
VAC_LAYOUT( Input_t, m_unStubValue, 0x64 );
VAC_LAYOUT( Report_t, m_unMagic, 0x10 );
VAC_LAYOUT( Report_t, m_unTimingCheck, 0x14 );
VAC_LAYOUT( Report_t, m_unBeingDebugged, 0x18 );
VAC_LAYOUT_SIZE( Report_t, 0x20 );
VAC_LAYOUT( Stub_t, m_unImmediate, 1 );
VAC_LAYOUT_SIZE( Stub_t, 6 );

} // namespace vac::workers::timing_check
