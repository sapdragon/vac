// @binary: 1da8fb5c
#include "internal/types.hpp"
#include "crt/intrinsics.hpp"

namespace vac::workers::system_handles
{

namespace
{

constexpr u32 k_cubStringPool = 0x4000;
constexpr int k_cMaxStrings = 500;

// @orig: 1da8fb5c:0x1000562F (no unique signature)
void *AllocateMemory( SIZE_T cubMemory ) noexcept
{
	return HeapAlloc( GetProcessHeap(), 0, cubMemory );
}

// @orig: 52 85 C9 74
void *ReallocateMemory( void *pMemory, SIZE_T cubMemory ) noexcept
{
	if ( pMemory )
		return HeapReAlloc( GetProcessHeap(), 0, pMemory, cubMemory );
	return HeapAlloc( GetProcessHeap(), 0, cubMemory );
}

// @orig: 56 8B F1 8B 56
void GrowHashVector( HashVector_t &vector ) noexcept
{
	if ( vector.m_cHashes == vector.m_cCapacity )
	{
		vector.m_cCapacity += 128;
		vector.m_punHashes =
		    static_cast<u32 *>( ReallocateMemory( vector.m_punHashes, sizeof( u32 ) * vector.m_cCapacity ) );
	}
}

// @orig: 8B 11 33 C0 56
int FindString( const StringTable_t &table, u32 unHash ) noexcept
{
	for ( int iEntry = 0; iEntry < table.m_cEntries; ++iEntry )
	{
		if ( table.m_pEntries[iEntry].m_unHash == unHash )
			return iEntry;
	}
	return -1;
}

// @orig: 83 EC ? 55 8B E9
void SortByRefs( StringTable_t &table ) noexcept
{
	for ( int iLeft = 0; iLeft < table.m_cEntries; ++iLeft )
	{
		for ( int iRight = iLeft + 1; iRight < table.m_cEntries; ++iRight )
		{
			if ( table.m_pEntries[iLeft].m_cRefs < table.m_pEntries[iRight].m_cRefs )
			{
				const StringEntry_t temp = table.m_pEntries[iLeft];
				table.m_pEntries[iLeft] = table.m_pEntries[iRight];
				table.m_pEntries[iRight] = temp;
			}
		}
	}
}

// @orig: 53 8B D9 33 D2
bool CopyString( const StringTable_t &table, u32 unHash, u8 **ppubCursor, int *pcubLeft ) noexcept
{
	for ( int iEntry = 0; iEntry < table.m_cEntries; ++iEntry )
	{
		const StringEntry_t &entry = table.m_pEntries[iEntry];
		if ( entry.m_unHash == unHash && entry.m_cchText < *pcubLeft )
		{
			u8 *pubCursor = *ppubCursor;
			*pcubLeft = *pcubLeft - entry.m_cchText - 1;
			// @note / sapdragon: text stays null when the pool was full, this faults. valve bug, keep it
			memcpy( pubCursor, entry.m_pszText, entry.m_cchText + 1 );
			*ppubCursor = pubCursor + entry.m_cchText + 1;
			return true;
		}
	}
	return false;
}

} // namespace

// @orig: 1da8fb5c:0x10005640 (no unique signature)
void FreeMemory( void *pMemory ) noexcept
{
	HeapFree( GetProcessHeap(), 0, pMemory );
}

// @orig: 56 8B F1 B9
void ConstructStringTable( StringTable_t &table ) noexcept
{
	table.m_pubPool = static_cast<char *>( AllocateMemory( k_cubStringPool ) );
	table.m_pubCursor = table.m_pubPool;
	table.m_pEntries = static_cast<StringEntry_t *>( AllocateMemory( k_cMaxStrings * sizeof( StringEntry_t ) ) );
	table.m_cubUsed = 0;
	table.m_cEntries = 0;
}

// @orig: 56 8B F1 8B 4E
void DestructStringTable( StringTable_t &table ) noexcept
{
	FreeMemory( table.m_pubPool );
	FreeMemory( table.m_pEntries );
}

// @orig: 53 8B 5C 24 ? 33 C0
void AddString( StringTable_t &table, u32 unHash, const char *pszText, int cchText ) noexcept
{
	for ( int iEntry = 0; iEntry < table.m_cEntries; ++iEntry )
	{
		if ( table.m_pEntries[iEntry].m_unHash == unHash )
		{
			++table.m_pEntries[iEntry].m_cRefs;
			return;
		}
	}

	if ( table.m_cEntries >= k_cMaxStrings )
		return;

	StringEntry_t &entry = table.m_pEntries[table.m_cEntries];
	entry.m_unHash = unHash;
	entry.m_cRefs = 1;
	entry.m_pszText = nullptr;
	entry.m_cchText = cchText;
	entry.m_bSelected = false;
	if ( pszText && static_cast<u32>( cchText + table.m_cubUsed + 1 ) < k_cubStringPool )
	{
		memcpy( table.m_pubCursor, pszText, cchText );
		table.m_pubCursor[cchText] = 0;
		entry.m_pszText = table.m_pubCursor;
		table.m_pubCursor += cchText + 1;
		table.m_cubUsed += cchText + 1;
	}
	++table.m_cEntries;
}

// @orig: 56 57 8B F9 E8
void AppendHash( HashVector_t &vector, u32 unHash ) noexcept
{
	GrowHashVector( vector );
	vector.m_punHashes[vector.m_cHashes++] = unHash;
}

// @orig: 83 EC ? 55 57
void EmitStrings( StringTable_t &baseNames, StringTable_t &directories, HashVector_t &directoryHashes,
                  HashVector_t &baseNameHashes, int cubBudget, u8 *pubCursor ) noexcept
{
	if ( !directories.m_cEntries )
		return;

	int cubMarked = cubBudget;
	SortByRefs( directories );

	// @note / sapdragon: starts at the least referenced directory and walks up. a percentile with 100 hardcoded
	int iDirectory = ( 100 * directories.m_cEntries - 100 ) / 100;
	const int iLast = ( iDirectory + 1 ) % directories.m_cEntries;
	if ( directories.m_cEntries > 0 )
	{
		int cVisited = 0;
		do
		{
			for ( int iHash = 0; iHash < directoryHashes.m_cHashes; ++iHash )
			{
				if ( FindString( directories, directoryHashes.m_punHashes[iHash] ) != iDirectory )
					continue;

				const int iBaseName = FindString( baseNames, baseNameHashes.m_punHashes[iHash] );
				if ( !baseNames.m_pEntries[iBaseName].m_bSelected )
				{
					cubMarked += -1 - baseNames.m_pEntries[iBaseName].m_cchText;
					if ( cubMarked < 0 )
						break;
					if ( iBaseName >= 0 && iBaseName < baseNames.m_cEntries )
						baseNames.m_pEntries[iBaseName].m_bSelected = true;
				}
			}

			cubMarked += -1 - directories.m_pEntries[iDirectory].m_cchText;
			if ( cubMarked < 0 )
				break;
			if ( iDirectory >= 0 && iDirectory < directories.m_cEntries )
				directories.m_pEntries[iDirectory].m_bSelected = true;
			if ( iDirectory == iLast )
				break;

			++cVisited;
			iDirectory = ( iDirectory - 1 >= 0 ? iDirectory : directories.m_cEntries ) - 1;
		} while ( cVisited < directories.m_cEntries );
	}

	int cubLeft = cubBudget;
	for ( int iHash = 0; iHash < directoryHashes.m_cHashes; ++iHash )
	{
		const int iBaseName = FindString( baseNames, baseNameHashes.m_punHashes[iHash] );
		if ( iBaseName >= 0 && baseNames.m_pEntries[iBaseName].m_bSelected )
		{
			if ( iBaseName < baseNames.m_cEntries )
				baseNames.m_pEntries[iBaseName].m_bSelected = false;
			if ( CopyString( baseNames, baseNameHashes.m_punHashes[iHash], &pubCursor, &cubLeft ) )
				baseNameHashes.m_punHashes[iHash] = 0;
		}

		const int iSelected = FindString( directories, directoryHashes.m_punHashes[iHash] );
		if ( iSelected >= 0 && directories.m_pEntries[iSelected].m_bSelected )
		{
			if ( iSelected < directories.m_cEntries )
				directories.m_pEntries[iSelected].m_bSelected = false;

			// @note / sapdragon: a directory hash found among the base names counts as sent without being copied. valve's quirk
			const u32 unHash = directoryHashes.m_punHashes[iHash];
			if ( FindString( baseNames, unHash ) >= 0 || CopyString( directories, unHash, &pubCursor, &cubLeft ) )
				directoryHashes.m_punHashes[iHash] = 0;
		}
	}
}

} // namespace vac::workers::system_handles
