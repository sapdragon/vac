#pragma once

#include "core/layout.hpp"
#include "core/types.hpp"

namespace vac::workers::driver_inventory
{

struct StringEntry_t
{
	u32 m_unHash;
	const char *m_pszText;
	i32 m_cubText;
	i32 m_cUses;
	bool m_bSelected;
};
VAC_LAYOUT( StringEntry_t, m_pszText, 0x04 );
VAC_LAYOUT( StringEntry_t, m_cubText, 0x08 );
VAC_LAYOUT( StringEntry_t, m_cUses, 0x0C );
VAC_LAYOUT( StringEntry_t, m_bSelected, 0x10 );
VAC_LAYOUT_SIZE( StringEntry_t, 20 );

struct StringTable_t
{
	i32 m_cEntries;
	StringEntry_t *m_pEntries;
	char *m_pchText;
	char *m_pchTextEnd;
	i32 m_cubText;
};
VAC_LAYOUT( StringTable_t, m_pEntries, 0x04 );
VAC_LAYOUT( StringTable_t, m_pchText, 0x08 );
VAC_LAYOUT( StringTable_t, m_pchTextEnd, 0x0C );
VAC_LAYOUT( StringTable_t, m_cubText, 0x10 );
VAC_LAYOUT_SIZE( StringTable_t, 20 );

struct HashVector_t
{
	u32 *m_punData;
	u32 m_cCapacity;
	u32 m_cHashes;
};
VAC_LAYOUT_SIZE( HashVector_t, 12 );

void *Reallocate( void *pMemory, usize cubSize ) noexcept;
void PushHash( HashVector_t &hashes, u32 unHash ) noexcept;
void InitStringTable( StringTable_t &table ) noexcept;
void DestroyStringTable( StringTable_t &table ) noexcept;
void AddString( StringTable_t &table, u32 unHash, const void *pubText, i32 cubText ) noexcept;
i32 FindStringByHash( const StringTable_t &table, u32 unHash ) noexcept;
void SortStringsByUses( StringTable_t &table ) noexcept;
bool EmitString( const StringTable_t &table, u32 unHash, u8 **ppubBlob, i32 *pcubBlob ) noexcept;
void PackDriverStringTables( StringTable_t &names, StringTable_t &paths, HashVector_t &pathHashes,
                             HashVector_t &nameHashes, i32 cubBlob, u8 *pubBlob ) noexcept;

} // namespace vac::workers::driver_inventory
