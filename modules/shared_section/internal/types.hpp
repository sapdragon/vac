#pragma once

#include "bootstrap/imports.hpp"
#include "core/layout.hpp"
#include "core/packets.hpp"
#include "core/scan_status.hpp"

namespace vac::workers::shared_section
{

inline constexpr u32 k_unModuleId = 0x0E3481C0;
inline constexpr u32 k_unReportMagic = 0x908D62F2;

// @note / sapdragon: these are __LINE__ values from valve's source, not real error codes
enum class EFailureLine : u32
{
	OpenFileMappingMissing = 390,
	MapViewMissing = 400,
	UnmapViewMissing = 410,
	OpenFailed = 440,
	SectionNotFound = 466,
	MapViewFailed = 483,
};

#pragma pack( push, 1 )
struct Input_t
{
	u8 m_rgubBootstrap[96];
	u32 m_unIdentifier;
	u8 m_rgubReserved[60];
};

struct Report_t
{
	u8 m_rgubDispatcher[16];
	u32 m_unMagic;
	EScanStatus m_eStatus;
	union
	{
		// @note / sapdragon: still no idea who writes this mapping or what the format is
		u8 m_rgubMappedPayload[4072];
		struct
		{
			u8 m_rgubUnused0[12];
			u32 m_unIdentifierA;
			u32 m_unIdentifierB;
			u8 m_rgubUnused1[4];
			EFailureLine m_eFailureLine;
		};
	};
};
#pragma pack( pop )
VAC_LAYOUT( Input_t, m_unIdentifier, 0x60 );
VAC_LAYOUT_SIZE( Input_t, 160 );
VAC_LAYOUT( Report_t, m_unMagic, 0x10 );
VAC_LAYOUT( Report_t, m_eStatus, 0x14 );
VAC_LAYOUT( Report_t, m_rgubMappedPayload, 24 );
VAC_LAYOUT( Report_t, m_unIdentifierA, 0x24 );
VAC_LAYOUT( Report_t, m_unIdentifierB, 0x28 );
VAC_LAYOUT( Report_t, m_eFailureLine, 0x30 );
VAC_LAYOUT_SIZE( Report_t, k_cubReport );

void FormatMappingName( u32 unIdentifier, wchar_t *pwszName ) noexcept;
void ReadMapping( const Input_t &input, Report_t &report, const SystemImports_t *pImports ) noexcept;

} // namespace vac::workers::shared_section
