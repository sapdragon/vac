#pragma once

#include "bootstrap/imports.hpp"
#include "core/layout.hpp"
#include "core/packets.hpp"
#include "core/scan_status.hpp"

namespace vac::workers::cpuid
{

inline constexpr u32 k_unModuleId = 0x023429C3;
inline constexpr u32 k_unReportMagic = 0xDECBE74A;
inline constexpr u32 k_cMaxRecords = 169;

enum class EAppendResult
{
	Appended,
	RecordsFull,
	CpuidUnsupported,
};

#pragma pack( push, 1 )
struct Input_t
{
	u8 m_rgubBootstrap[8];
	u8 m_rgubReserved[152];
};

struct CpuidRecord_t
{
	u32 m_unLeaf;
	u32 m_unSubleaf;
	u32 m_unEax;
	u32 m_unEbx;
	u32 m_unEcx;
	u32 m_unEdx;
};

struct Report_t
{
	u8 m_rgubDispatcher[16];
	u32 m_unMagic;
	EScanStatus m_eStatus;
	u32 m_unReserved18;
	u32 m_cRecords;
	u8 m_rgubReserved20[8];
	CpuidRecord_t m_rgRecords[k_cMaxRecords];
};
#pragma pack( pop )
VAC_LAYOUT_SIZE( Input_t, k_cubEncryptedConfig );
VAC_LAYOUT( Report_t, m_unMagic, 0x10 );
VAC_LAYOUT( Report_t, m_eStatus, 0x14 );
VAC_LAYOUT( Report_t, m_unReserved18, 0x18 );
VAC_LAYOUT( Report_t, m_cRecords, 0x1C );
VAC_LAYOUT( Report_t, m_rgRecords, 0x28 );
VAC_LAYOUT_SIZE( CpuidRecord_t, 24 );
VAC_LAYOUT_SIZE( Report_t, k_cubReport );

using PfnContinue_t = BOOL( __cdecl * )( const CpuidRecord_t *pFirst, const CpuidRecord_t *pCurrent );

struct LeafRule_t
{
	u32 m_unLeaf;
	PfnContinue_t m_pfnContinue;
};

int Cpuid( u32 *punEax, u32 *punEbx, u32 *punEcx, u32 *punEdx ) noexcept;
BOOL __cdecl ContinueCacheSubleaf( const CpuidRecord_t *pFirst, const CpuidRecord_t *pCurrent ) noexcept;
BOOL __cdecl ContinueSubleafBelowFirstEax( const CpuidRecord_t *pFirst, const CpuidRecord_t *pCurrent ) noexcept;
BOOL __cdecl ContinueEaxOrEbx( const CpuidRecord_t *pFirst, const CpuidRecord_t *pCurrent ) noexcept;
BOOL __cdecl ContinueXsave( const CpuidRecord_t *pFirst, const CpuidRecord_t *pCurrent ) noexcept;
BOOL __cdecl ContinueRdtMonitoring( const CpuidRecord_t *pFirst, const CpuidRecord_t *pCurrent ) noexcept;
BOOL __cdecl ContinueRdtAllocation( const CpuidRecord_t *pFirst, const CpuidRecord_t *pCurrent ) noexcept;
EAppendResult AppendLeaf( Report_t &report, u32 *pcRecords, u32 *punMaxLeaf, u32 unLeaf,
                          PfnContinue_t pfnContinue ) noexcept;
EScanStatus Collect( Report_t &report ) noexcept;

} // namespace vac::workers::cpuid
