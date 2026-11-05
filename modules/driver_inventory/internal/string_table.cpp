// @binary: 2023d8c3
#include "internal/string_table.hpp"
#include "bootstrap/imports.hpp"
#include "core/vac_util.hpp"
#include "crt/intrinsics.hpp"

namespace vac::workers::driver_inventory
{

namespace
{

constexpr i32 k_cMaxStrings = 500;
constexpr i32 k_cubStringText = 0x4000;

} // namespace

// @orig: 52 85 C9 74
void *Reallocate( void *pMemory, usize cubSize ) noexcept
{
	if ( pMemory )
		return HeapReAlloc( GetProcessHeap(), 0, pMemory, cubSize );
	return HeapAlloc( GetProcessHeap(), 0, cubSize );
}

// @orig: 56 8B F1 8B 56
static void EnsureHashCapacity( HashVector_t &hashes ) noexcept
{
	if ( hashes.m_cHashes == hashes.m_cCapacity )
	{
		hashes.m_cCapacity += 128;
		hashes.m_punData = static_cast<u32 *>( Reallocate( hashes.m_punData, hashes.m_cCapacity * sizeof( u32 ) ) );
	}
}

// @orig: 56 57 8B F9 E8
void PushHash( HashVector_t &hashes, u32 unHash ) noexcept
{
	EnsureHashCapacity( hashes );
	hashes.m_punData[hashes.m_cHashes++] = unHash;
}

// @orig: 56 8B F1 B9
void InitStringTable( StringTable_t &table ) noexcept
{
	table.m_pchText = static_cast<char *>( util::HeapAlloc( k_cubStringText ) );
	table.m_pchTextEnd = table.m_pchText;
	table.m_pEntries = static_cast<StringEntry_t *>( util::HeapAlloc( sizeof( StringEntry_t ) * k_cMaxStrings ) );
	table.m_cubText = 0;
	table.m_cEntries = 0;
}

// @orig: 56 8B F1 8B 4E
void DestroyStringTable( StringTable_t &table ) noexcept
{
	util::HeapFree( table.m_pchText );
	util::HeapFree( table.m_pEntries );
}

// @orig: 53 8B 5C 24 ? 33 C0
void AddString( StringTable_t &table, u32 unHash, const void *pubText, i32 cubText ) noexcept
{
	for ( i32 iEntry = 0; iEntry < table.m_cEntries; ++iEntry )
	{
		if ( table.m_pEntries[iEntry].m_unHash == unHash )
		{
			++table.m_pEntries[iEntry].m_cUses;
			return;
		}
	}

	if ( table.m_cEntries >= k_cMaxStrings )
		return;

	StringEntry_t &entry = table.m_pEntries[table.m_cEntries];
	entry.m_unHash = unHash;
	entry.m_cUses = 1;
	entry.m_pszText = nullptr;
	entry.m_cubText = cubText;
	entry.m_bSelected = false;

	if ( pubText && cubText + table.m_cubText + 1 < k_cubStringText )
	{
		memcpy( table.m_pchTextEnd, pubText, cubText );
		table.m_pchTextEnd[cubText] = 0;
		entry.m_pszText = table.m_pchTextEnd;
		table.m_pchTextEnd += cubText + 1;
		table.m_cubText += cubText + 1;
	}
	++table.m_cEntries;
}

// @orig: 8B 11 33 C0 56
i32 FindStringByHash( const StringTable_t &table, u32 unHash ) noexcept
{
	for ( i32 iEntry = 0; iEntry < table.m_cEntries; ++iEntry )
	{
		if ( table.m_pEntries[iEntry].m_unHash == unHash )
			return iEntry;
	}
	return -1;
}

// @orig: 83 EC ? 55 8B E9
void SortStringsByUses( StringTable_t &table ) noexcept
{
	for ( i32 iEntry = 0; iEntry < table.m_cEntries; ++iEntry )
	{
		for ( i32 iOther = iEntry + 1; iOther < table.m_cEntries; ++iOther )
		{
			if ( table.m_pEntries[iEntry].m_cUses < table.m_pEntries[iOther].m_cUses )
			{
				const StringEntry_t entry = table.m_pEntries[iEntry];
				table.m_pEntries[iEntry] = table.m_pEntries[iOther];
				table.m_pEntries[iOther] = entry;
			}
		}
	}
}

// @orig: 53 8B D9 33 D2
bool EmitString( const StringTable_t &table, u32 unHash, u8 **ppubBlob, i32 *pcubBlob ) noexcept
{
	for ( i32 iEntry = 0; iEntry < table.m_cEntries; ++iEntry )
	{
		const StringEntry_t &entry = table.m_pEntries[iEntry];
		if ( entry.m_unHash == unHash && entry.m_cubText < *pcubBlob )
		{
			u8 *pubBlob = *ppubBlob;
			*pcubBlob = *pcubBlob - entry.m_cubText - 1;
			memcpy( pubBlob, entry.m_pszText, entry.m_cubText + 1 );
			*ppubBlob = pubBlob + entry.m_cubText + 1;
			return true;
		}
	}
	return false;
}

// @orig: 83 EC ? 55 57
void PackDriverStringTables( StringTable_t &names, StringTable_t &paths, HashVector_t &pathHashes,
                             HashVector_t &nameHashes, i32 cubBlob, u8 *pubBlob ) noexcept
{
	if ( !paths.m_cEntries )
		return;

	i32 cubBudget = cubBlob;
	SortStringsByUses( paths );

	// @note / sapdragon: starts at the least used path and walks back to the most used one, whole strings only.
	// a name that does not fit stops that row, but the names it already picked stay picked
	i32 iPath = ( 100 * paths.m_cEntries - 100 ) / 100;
	const i32 iLastPath = ( iPath + 1 ) % paths.m_cEntries;
	for ( i32 cVisited = 0; cVisited < paths.m_cEntries; ++cVisited )
	{
		for ( u32 iRow = 0; iRow < pathHashes.m_cHashes; ++iRow )
		{
			if ( FindStringByHash( paths, pathHashes.m_punData[iRow] ) != iPath )
				continue;

			const i32 iName = FindStringByHash( names, nameHashes.m_punData[iRow] );
			if ( !names.m_pEntries[iName].m_bSelected )
			{
				cubBudget -= names.m_pEntries[iName].m_cubText + 1;
				if ( cubBudget < 0 )
					break;
				if ( iName >= 0 && iName < names.m_cEntries )
					names.m_pEntries[iName].m_bSelected = true;
			}
		}

		cubBudget -= paths.m_pEntries[iPath].m_cubText + 1;
		if ( cubBudget < 0 )
			break;
		if ( iPath >= 0 && iPath < paths.m_cEntries )
			paths.m_pEntries[iPath].m_bSelected = true;
		if ( iPath == iLastPath )
			break;
		iPath = iPath - 1 >= 0 ? iPath - 1 : paths.m_cEntries - 1;
	}

	i32 cubLeft = cubBlob;
	for ( u32 iRow = 0; iRow < pathHashes.m_cHashes; ++iRow )
	{
		const i32 iName = FindStringByHash( names, nameHashes.m_punData[iRow] );
		if ( iName >= 0 && names.m_pEntries[iName].m_bSelected )
		{
			if ( iName < names.m_cEntries )
				names.m_pEntries[iName].m_bSelected = false;
			if ( EmitString( names, nameHashes.m_punData[iRow], &pubBlob, &cubLeft ) )
				nameHashes.m_punData[iRow] = 0;
		}

		const i32 iPathRow = FindStringByHash( paths, pathHashes.m_punData[iRow] );
		if ( iPathRow >= 0 && paths.m_pEntries[iPathRow].m_bSelected )
		{
			if ( iPathRow < paths.m_cEntries )
				paths.m_pEntries[iPathRow].m_bSelected = false;

			// @note / sapdragon: a hash that is also a name counts as emitted, the path text never goes in
			const u32 unHash = pathHashes.m_punData[iRow];
			if ( FindStringByHash( names, unHash ) >= 0 || EmitString( paths, unHash, &pubBlob, &cubLeft ) )
				pathHashes.m_punData[iRow] = 0;
		}
	}
}

} // namespace vac::workers::driver_inventory
