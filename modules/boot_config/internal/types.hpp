#pragma once

#include "bootstrap/imports.hpp"
#include "core/layout.hpp"
#include "core/packets.hpp"
#include "core/scan_status.hpp"

namespace vac::workers::boot_config
{

inline constexpr u32 k_unModuleId = 0x06A79A9E;
inline constexpr u32 k_unReportMagic = 0x37FCB2BC;

#pragma pack( push, 1 )
struct KeyPath_t
{
	char m_rgchObjects[19];
	char m_rgchGuidPrefix[2];
	char m_rgchGuid[36];
	char m_rgchElements[11];
	char m_rgchElementId[8];
	char m_chTerminator;
};

struct Input_t
{
	u8 m_rgubBootstrap[0x20];
	char m_rgchEncodedGuid[36];
	u8 m_rgubReserved[0x5C];
};

struct Element_t
{
	u8 m_ubOpenStatus;
	u8 m_ubQueryStatus;
	u8 m_ubFileOpenError;
	u8 m_ubFileInfoError;
	u8 m_rgubReserved[3];
	u8 m_cubValue;
	u32 m_unPathHash;
	u32 m_unDescriptionHash;
	char m_szValue[32];
	u32 m_unFileIndexLow;
	u32 m_unFileIndexHigh;
};

struct Report_t
{
	u8 m_rgubDispatcher[16];
	u32 m_unMagic;
	EScanStatus m_eStatus;

	u32 m_unStatus12000002;
	u32 m_unStatus22000011;
	u32 m_unStatus12000030;
	u32 m_unStatus22000012;
	u32 m_unStatus16000049;
	u32 m_unStatus25000020;
	u32 m_unStatus16000048;
	u32 m_unVolumeSerial;

	u32 m_unFileIndexLow12000002;
	u32 m_unFileIndexHigh12000002;
	u32 m_unFileIndexLow22000011;
	u32 m_unFileIndexHigh22000011;
	u32 m_unFileIndexLow22000012;
	u32 m_unFileIndexHigh22000012;
	u64 m_ulValue25000020;
	u32 m_unValue16000048;
	u32 m_unValue16000049;

	char m_szValue12000002[32];
	char m_szValue22000011[32];
	char m_szValue22000012[32];
	char m_szValue12000030[32];

	u32 m_unStatus12000004;
	u32 m_unVersion;
	char m_szValue12000004[32];
	u32 m_unReserved0;

	char m_szCurrentGuid[36];
	Element_t m_Element12000002;
	Element_t m_Element22000011;
	Element_t m_Element22000012;
	Element_t m_Element12000004;

	u32 m_unObjectsOpenStatus;
	u32 m_cSubKeys;
	u32 m_cValues;
	u32 m_unReserved1;
	FILETIME m_ftObjectsLastWrite;
	u32 m_unObjectsQueryStatus;
	u32 m_cObjects;
	char m_rgszObjectGuid[32][36];
	Element_t m_rgObjects[32];
};
#pragma pack( pop )
VAC_LAYOUT( KeyPath_t, m_rgchGuid, 0x15 );
VAC_LAYOUT( KeyPath_t, m_rgchElementId, 0x44 );
VAC_LAYOUT_SIZE( KeyPath_t, 0x4D );
VAC_LAYOUT_SIZE( Input_t, 160 );
VAC_LAYOUT( Input_t, m_rgchEncodedGuid, 0x20 );
VAC_LAYOUT_SIZE( Element_t, 0x38 );
VAC_LAYOUT( Element_t, m_cubValue, 0x07 );
VAC_LAYOUT( Element_t, m_unPathHash, 0x08 );
VAC_LAYOUT( Element_t, m_unDescriptionHash, 0x0C );
VAC_LAYOUT( Element_t, m_szValue, 0x10 );
VAC_LAYOUT( Element_t, m_unFileIndexLow, 0x30 );
VAC_LAYOUT( Element_t, m_unFileIndexHigh, 0x34 );
VAC_LAYOUT( Report_t, m_unMagic, 0x10 );
VAC_LAYOUT( Report_t, m_eStatus, 0x14 );
VAC_LAYOUT( Report_t, m_unStatus12000002, 0x18 );
VAC_LAYOUT( Report_t, m_unStatus12000030, 0x20 );
VAC_LAYOUT( Report_t, m_unVolumeSerial, 0x34 );
VAC_LAYOUT( Report_t, m_unFileIndexLow12000002, 0x38 );
VAC_LAYOUT( Report_t, m_ulValue25000020, 0x50 );
VAC_LAYOUT( Report_t, m_unValue16000048, 0x58 );
VAC_LAYOUT( Report_t, m_unValue16000049, 0x5C );
VAC_LAYOUT( Report_t, m_szValue12000002, 0x60 );
VAC_LAYOUT( Report_t, m_szValue12000030, 0xC0 );
VAC_LAYOUT( Report_t, m_unStatus12000004, 0xE0 );
VAC_LAYOUT( Report_t, m_unVersion, 0xE4 );
VAC_LAYOUT( Report_t, m_szValue12000004, 0xE8 );
VAC_LAYOUT( Report_t, m_szCurrentGuid, 0x10C );
VAC_LAYOUT( Report_t, m_Element12000002, 0x130 );
VAC_LAYOUT( Report_t, m_Element22000011, 0x168 );
VAC_LAYOUT( Report_t, m_Element22000012, 0x1A0 );
VAC_LAYOUT( Report_t, m_Element12000004, 0x1D8 );
VAC_LAYOUT( Report_t, m_unObjectsOpenStatus, 0x210 );
VAC_LAYOUT( Report_t, m_ftObjectsLastWrite, 0x220 );
VAC_LAYOUT( Report_t, m_unObjectsQueryStatus, 0x228 );
VAC_LAYOUT( Report_t, m_cObjects, 0x22C );
VAC_LAYOUT( Report_t, m_rgszObjectGuid, 0x230 );
VAC_LAYOUT( Report_t, m_rgObjects, 0x6B0 );
VAC_LAYOUT_SIZE( Report_t, 0xDB0 );

int ReadElement( char *pszKeyPath, const char *pszElementId, const char *pszValueName, bool bFileCheck,
                 Element_t *pElement, u32 *punHash ) noexcept;
void EnumerateObjects( Report_t &report, char *pszKeyPath, const char *pszValueName ) noexcept;

} // namespace vac::workers::boot_config
