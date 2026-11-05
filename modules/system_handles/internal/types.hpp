#pragma once

#include "bootstrap/imports.hpp"
#include "core/enum.hpp"
#include "core/layout.hpp"
#include "core/packets.hpp"
#include "core/scan_status.hpp"

namespace vac::workers::system_handles
{

inline constexpr u32 k_unModuleId = 0x002F6DC7;
inline constexpr int k_cMaxPids = 500;

enum class EInputFlags : u32
{
	IncludeExited = 1,
	FilterByAge = 2,
	LimitStrings = 4,
};
VAC_FLAGS( EInputFlags )

// @note / sapdragon: parent pids are multiples of 4, so valve packs these into the low bits of the same field
enum class ERecordFlags : u32
{
	BaseNameEmitted = 0x00000001,
	DirectoryEmitted = 0x00000002,
	Exited = 0x20000000,
	NotInSnapshot = 0x40000000,
	OpenFailed = 0x80000000,
};
VAC_FLAGS( ERecordFlags )

#pragma pack( push, 1 )
struct Input_t
{
	u8 m_rgubBootstrap[32];
	u32 m_unMinPid;
	u32 m_unMaxPid;
	u32 m_unMaxAgeSeconds;
	EInputFlags m_eFlags;
	u8 m_rgubReserved[112];
};

struct ProcessRecord_t
{
	u32 m_unDirectoryHash;
	u32 m_unBaseNameHash;
	u32 m_unPid;
	u32 m_unParentPidAndFlags;
	u32 m_unHandleMaskLow;
	u32 m_unHandleMaskHigh;
	u32 m_unCreateSecondsOrError;
};

struct Report_t
{
	u8 m_rgubDispatcher[16];
	EScanStatus m_eStatus;
	u32 m_unUnused0;
	u32 m_cOpened;
	u32 m_unReportType;
	u32 m_unUnused1;
	u32 m_cRecords;
	u32 m_cExtraPids;
	u32 m_cSystemHandles;
	EScanStatus m_eHandleQueryStatus;
	u32 m_unScanTimeSeconds;
	u32 m_unPackedVersion;
	u32 m_cEnumerated;
	ProcessRecord_t m_rgRecords[144];
};
#pragma pack( pop )
VAC_LAYOUT( Input_t, m_unMinPid, 0x20 );
VAC_LAYOUT( Input_t, m_unMaxPid, 0x24 );
VAC_LAYOUT( Input_t, m_unMaxAgeSeconds, 0x28 );
VAC_LAYOUT( Input_t, m_eFlags, 0x2C );
VAC_LAYOUT_SIZE( Input_t, 160 );
VAC_LAYOUT( ProcessRecord_t, m_unParentPidAndFlags, 0x0C );
VAC_LAYOUT( ProcessRecord_t, m_unCreateSecondsOrError, 0x18 );
VAC_LAYOUT_SIZE( ProcessRecord_t, 28 );
VAC_LAYOUT( Report_t, m_eStatus, 0x10 );
VAC_LAYOUT( Report_t, m_cOpened, 0x18 );
VAC_LAYOUT( Report_t, m_unReportType, 0x1C );
VAC_LAYOUT( Report_t, m_cRecords, 0x24 );
VAC_LAYOUT( Report_t, m_cExtraPids, 0x28 );
VAC_LAYOUT( Report_t, m_cSystemHandles, 0x2C );
VAC_LAYOUT( Report_t, m_eHandleQueryStatus, 0x30 );
VAC_LAYOUT( Report_t, m_unScanTimeSeconds, 0x34 );
VAC_LAYOUT( Report_t, m_unPackedVersion, 0x38 );
VAC_LAYOUT( Report_t, m_cEnumerated, 0x3C );
VAC_LAYOUT( Report_t, m_rgRecords, 0x40 );
VAC_LAYOUT_SIZE( Report_t, k_cubReport );

struct StringEntry_t
{
	u32 m_unHash;
	char *m_pszText;
	int m_cchText;
	int m_cRefs;
	bool m_bSelected;
};
VAC_LAYOUT( StringEntry_t, m_bSelected, 16 );
VAC_LAYOUT_SIZE( StringEntry_t, 20 );

struct StringTable_t
{
	int m_cEntries;
	StringEntry_t *m_pEntries;
	char *m_pubPool;
	char *m_pubCursor;
	int m_cubUsed;
};
VAC_LAYOUT_SIZE( StringTable_t, 20 );

struct HashVector_t
{
	u32 *m_punHashes;
	int m_cCapacity;
	int m_cHashes;
};
VAC_LAYOUT_SIZE( HashVector_t, 12 );

// @note / sapdragon: low bits of the high half are object types 32 to 54, the top byte counts handles and stops at 0xFF
struct HandleMask_t
{
	u32 m_unLow;
	u32 m_unHigh;
};

struct ScanContext_t
{
	u32 m_unMinPid;
	u32 m_unMaxPid;
	bool m_bIncludeExited;
	bool m_bFilterByAge;
	bool m_bLimitStrings;
	u32 m_unMaxAgeSeconds;
	Report_t *m_pReport;
	StringTable_t m_Directories;
	StringTable_t m_BaseNames;
	HashVector_t m_DirectoryHashes;
	HashVector_t m_BaseNameHashes;
	int m_cSnapshot;
	u32 m_rgunPids[k_cMaxPids];
	u32 m_rgunParentPids[k_cMaxPids];
	HandleMask_t m_rgMasks[k_cMaxPids];
	u32 m_unNowSeconds;
};
VAC_LAYOUT( ScanContext_t, m_unMaxAgeSeconds, 0x0C );
VAC_LAYOUT( ScanContext_t, m_pReport, 0x10 );
VAC_LAYOUT( ScanContext_t, m_Directories, 0x14 );
VAC_LAYOUT( ScanContext_t, m_BaseNames, 0x28 );
VAC_LAYOUT( ScanContext_t, m_DirectoryHashes, 0x3C );
VAC_LAYOUT( ScanContext_t, m_BaseNameHashes, 0x48 );
VAC_LAYOUT( ScanContext_t, m_cSnapshot, 0x54 );
VAC_LAYOUT( ScanContext_t, m_rgunPids, 0x58 );
VAC_LAYOUT( ScanContext_t, m_rgunParentPids, 0x828 );
VAC_LAYOUT( ScanContext_t, m_rgMasks, 0xFF8 );
VAC_LAYOUT( ScanContext_t, m_unNowSeconds, 0x1F98 );

void FreeMemory( void *pMemory ) noexcept;
void ConstructStringTable( StringTable_t &table ) noexcept;
void DestructStringTable( StringTable_t &table ) noexcept;
void AddString( StringTable_t &table, u32 unHash, const char *pszText, int cchText ) noexcept;
void AppendHash( HashVector_t &vector, u32 unHash ) noexcept;
void EmitStrings( StringTable_t &baseNames, StringTable_t &directories, HashVector_t &directoryHashes,
                  HashVector_t &baseNameHashes, int cubBudget, u8 *pubCursor ) noexcept;

void CollectReport( ScanContext_t &context, Report_t &report ) noexcept;

} // namespace vac::workers::system_handles
