#pragma once

#include "internal/process_context.hpp"
#include "internal/types.hpp"

namespace vac::workers::process_memory_map
{

struct U32Vector_t
{
	u32 *m_prgun;
	u32 m_cCapacity;
	i32 m_c;
};
VAC_LAYOUT( U32Vector_t, m_cCapacity, 0x04 );
VAC_LAYOUT( U32Vector_t, m_c, 0x08 );

struct StringEntry_t
{
	u32 m_unHash;
	i32 m_cUses;
	i32 m_nRank;
	const char *m_pszText;
	i32 m_cchText;
	bool m_bEmitted;
};
VAC_LAYOUT( StringEntry_t, m_nRank, 0x08 );
VAC_LAYOUT( StringEntry_t, m_pszText, 0x0C );
VAC_LAYOUT( StringEntry_t, m_bEmitted, 0x14 );
VAC_LAYOUT_SIZE( StringEntry_t, 24 );

struct StringTable_t
{
	i32 m_cEntries;
	StringEntry_t *m_pEntries;
	char *m_pchStorage;
	char *m_pchWrite;
	i32 m_cubUsed;
};

struct ReportBuilder_t
{
	u8 *m_pubRecords;
	u8 *m_pubRecordWrite;
	u8 *m_pubLastRecord;
	u8 *m_pubHashes;
	u8 *m_pubHashWrite;
	i32 m_cRecords;
	i32 m_cMaxRecords;
	i32 m_cHashes;
	i32 m_cMaxHashes;
	i32 m_cubStrings;
	U32Vector_t m_StringEnds;
	u8 m_rgubRecords[k_cMaxRecords * sizeof( ModuleRecord64_t )];
	u8 m_rgubHashes[k_cMaxHashes * sizeof( ImageHashRecord64_t )];
	char m_rgchStrings[0x800];
	i32 m_cubPlain;
	bool m_bWideRecords;
	u64 m_ulMinHashBase;
};
VAC_LAYOUT( ReportBuilder_t, m_cRecords, 0x14 );
VAC_LAYOUT( ReportBuilder_t, m_cHashes, 0x1C );
VAC_LAYOUT( ReportBuilder_t, m_cubStrings, 0x24 );
VAC_LAYOUT( ReportBuilder_t, m_StringEnds, 0x28 );
VAC_LAYOUT( ReportBuilder_t, m_rgubRecords, 0x34 );
VAC_LAYOUT( ReportBuilder_t, m_rgubHashes, 0x1F74 );
VAC_LAYOUT( ReportBuilder_t, m_rgchStrings, 0x23F4 );
VAC_LAYOUT( ReportBuilder_t, m_cubPlain, 0x2BF4 );
VAC_LAYOUT( ReportBuilder_t, m_bWideRecords, 0x2BF8 );
VAC_LAYOUT( ReportBuilder_t, m_ulMinHashBase, 0x2C00 );

struct SystemDirectories_t
{
	wchar_t m_wszWindows[MAX_PATH];
	i32 m_cchWindows;
	wchar_t m_wszSystem[MAX_PATH];
	i32 m_cchSystem;
};
VAC_LAYOUT( SystemDirectories_t, m_cchWindows, 0x208 );
VAC_LAYOUT( SystemDirectories_t, m_wszSystem, 0x20C );
VAC_LAYOUT( SystemDirectories_t, m_cchSystem, 0x414 );

struct PathEntry_t
{
	char m_szDirectory[MAX_PATH];
	char m_szBaseName[MAX_PATH];
	i32 m_cchDirectory;
	i32 m_cchBaseName;
	bool m_bInSystemDirectory;
	bool m_bInWindowsDirectory;
	u32 m_unDirectoryHash;
	u32 m_unBaseNameHash;
	bool m_bHasPath;
};
VAC_LAYOUT( PathEntry_t, m_cchDirectory, 0x208 );
VAC_LAYOUT( PathEntry_t, m_bInSystemDirectory, 0x210 );
VAC_LAYOUT( PathEntry_t, m_unDirectoryHash, 0x214 );
VAC_LAYOUT( PathEntry_t, m_bHasPath, 0x21C );

void ResetPathEntry( PathEntry_t &entry ) noexcept;
void BuildPathEntry( PathEntry_t &entry, const wchar_t *pwszPath, const SystemDirectories_t &directories,
                     const SystemImports_t *pImports ) noexcept;

void PushU32( U32Vector_t &vector, u32 unValue ) noexcept;
void InitStringTable( StringTable_t &table ) noexcept;
void AddString( StringTable_t &table, u32 unHash, const char *pszText, i32 cchText ) noexcept;
[[nodiscard]] i32 PackStrings( StringTable_t &baseNames, StringTable_t &directories, const U32Vector_t &directoryHashes,
                               const U32Vector_t &baseNameHashes, U32Vector_t &stringEnds, char *pchOutput ) noexcept;

[[nodiscard]] bool AppendRecord( ReportBuilder_t &builder, u64 ulBase, u8 unRegionCount, u32 unDirectoryHash,
                                 u32 unBaseNameHash, u32 cubImage, ERecordFlags eFlags, u16 unLdrIndex ) noexcept;
bool HashImageIntoTable( ReportBuilder_t &builder, const ProcessContext_t &context, const AllocationWalk_t &walk,
                         const wchar_t *pwszPath, const SystemImports_t *pImports ) noexcept;

[[nodiscard]] i32 GetPlainSize( ReportBuilder_t &builder ) noexcept;
[[nodiscard]] i32 GetRecordBytes( const ReportBuilder_t &builder ) noexcept;
[[nodiscard]] i32 CompressRecords( ReportBuilder_t &builder, u8 *pubOutput ) noexcept;

[[nodiscard]] EScanStatus ScanProcess( const ProcessContext_t &context, Report_t &report, u32 unScanStart,
                                       i32 nMaxHashes, i32 nTrimRatio, u32 unMinHashBase,
                                       const SystemImports_t *pImports ) noexcept;

} // namespace vac::workers::process_memory_map
