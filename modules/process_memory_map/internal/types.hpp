#pragma once

#include "bootstrap/imports.hpp"
#include "core/enum.hpp"
#include "core/layout.hpp"
#include "core/packets.hpp"
#include "core/scan_status.hpp"
#include "process/capture_flags.hpp"

namespace vac::workers::process_memory_map
{

inline constexpr u32 k_unModuleId = 0x06E048F4;
inline constexpr u32 k_cMaxRecords = 400;
inline constexpr i32 k_cMaxHashes = 32;

enum class EReportFlags : u16
{
	None = 0,
	SelfWow64 = 0x0001,
	Cross64 = 0x0002,
	WideRecords = 0x0004,
	TrimFailed = 0x0008,
};
VAC_FLAGS( EReportFlags )

enum class ERecordFlags : u32
{
	None = 0,
	InLdr = 0x0001,
	PathInLdr = 0x0002,
	PeImage = 0x0004,
	Named = 0x0010,
	HasText = 0x0020,
	Pe64 = 0x0040,
	Odd = 0x0080,
	WritableExecute = 0x0100,
	ValveStub = 0x0200,
	SystemDirectory = 0x0400,
	WindowsDirectory = 0x0800,
	// @note / sapdragon: a region with none of these and exactly one committed page gets folded into the previous
	// record
	NotClean = InLdr | PathInLdr | PeImage | Named,
	PeImageWithText = PeImage | HasText,
};
VAC_FLAGS( ERecordFlags )

enum class EHashSource : u32
{
	RawFile = 0,
	Memory = 4,
	NormalizedFile = 8,
};
VAC_FLAGS( EHashSource )

#pragma pack( push, 1 )
struct Input_t
{
	u8 m_rgubBootstrap[96];
	u32 m_unPid;
	u32 m_unScanStart;
	i32 m_nMaxHashes;
	i32 m_nTrimRatio;
	u32 m_unMinHashBase;
	u8 m_rgubReserved[44];
};

struct ImageHashRecord32_t
{
	u32 m_unBaseAndSource;
	u32 m_unVolumeSerial;
	u32 m_unFileIndexLow;
	u32 m_unFileIndexHigh;
	u8 m_rgubDigest[16];
};

struct ImageHashRecord64_t
{
	u32 m_unBaseAndSource;
	u32 m_unBaseHigh;
	u32 m_unVolumeSerial;
	u32 m_unFileIndexLow;
	u32 m_unFileIndexHigh;
	u8 m_rgubDigest[16];
};

struct ModuleRecord32_t
{
	u32 m_unDirectoryHash;
	u32 m_unBaseNameHash;
	u32 m_unBaseAndTag;
	u32 m_unSizeAndFlags;
};

struct ModuleRecord64_t
{
	u32 m_unDirectoryHash;
	u32 m_unBaseNameHash;
	u32 m_unBaseAndTag;
	u32 m_unBaseHigh;
	u32 m_unSizeAndFlags;
};

struct Report_t
{
	u8 m_rgubDispatcher[16];
	EScanStatus m_eStatus;
	process::ECaptureFlags m_eCaptureFlags;
	u32 m_unLastError;
	u32 m_unPid;
	u32 m_unScanType;
	u32 m_cRecordsScanned;
	u32 m_unScanStart;
	u32 m_unScanEnd;
	u16 m_cNamedOrPe;
	u16 m_cLdrModules;
	u16 m_cHashes;
	u16 m_cCleanRegions;
	u32 m_cLdrMatches;
	u32 m_cRecordsPacked;
	u64 m_ulCreateTime;
	u8 m_cHashesPacked;
	u8 m_unReserved;
	EReportFlags m_eFlags;
	u16 m_cRecords;
	u16 m_cubStrings;
	u32 m_cubCompressed;
	u32 m_cubPlain;
	u8 m_rgubCompressed[0xFA8];
};
#pragma pack( pop )

VAC_LAYOUT( Input_t, m_unPid, 0x60 );
VAC_LAYOUT( Input_t, m_unScanStart, 0x64 );
VAC_LAYOUT( Input_t, m_nMaxHashes, 0x68 );
VAC_LAYOUT( Input_t, m_nTrimRatio, 0x6C );
VAC_LAYOUT( Input_t, m_unMinHashBase, 0x70 );
VAC_LAYOUT_SIZE( Input_t, k_cubEncryptedConfig );

VAC_LAYOUT_SIZE( ImageHashRecord32_t, 0x20 );
VAC_LAYOUT_SIZE( ImageHashRecord64_t, 0x24 );
VAC_LAYOUT_SIZE( ModuleRecord32_t, 0x10 );
VAC_LAYOUT_SIZE( ModuleRecord64_t, 0x14 );

VAC_LAYOUT( Report_t, m_eStatus, 0x10 );
VAC_LAYOUT( Report_t, m_eCaptureFlags, 0x14 );
VAC_LAYOUT( Report_t, m_unLastError, 0x18 );
VAC_LAYOUT( Report_t, m_unPid, 0x1C );
VAC_LAYOUT( Report_t, m_unScanType, 0x20 );
VAC_LAYOUT( Report_t, m_cRecordsScanned, 0x24 );
VAC_LAYOUT( Report_t, m_unScanStart, 0x28 );
VAC_LAYOUT( Report_t, m_unScanEnd, 0x2C );
VAC_LAYOUT( Report_t, m_cNamedOrPe, 0x30 );
VAC_LAYOUT( Report_t, m_cLdrModules, 0x32 );
VAC_LAYOUT( Report_t, m_cHashes, 0x34 );
VAC_LAYOUT( Report_t, m_cCleanRegions, 0x36 );
VAC_LAYOUT( Report_t, m_cLdrMatches, 0x38 );
VAC_LAYOUT( Report_t, m_cRecordsPacked, 0x3C );
VAC_LAYOUT( Report_t, m_ulCreateTime, 0x40 );
VAC_LAYOUT( Report_t, m_cHashesPacked, 0x48 );
VAC_LAYOUT( Report_t, m_eFlags, 0x4A );
VAC_LAYOUT( Report_t, m_cRecords, 0x4C );
VAC_LAYOUT( Report_t, m_cubStrings, 0x4E );
VAC_LAYOUT( Report_t, m_cubCompressed, 0x50 );
VAC_LAYOUT( Report_t, m_cubPlain, 0x54 );
VAC_LAYOUT( Report_t, m_rgubCompressed, 0x58 );
VAC_LAYOUT_SIZE( Report_t, k_cubReport );

} // namespace vac::workers::process_memory_map
