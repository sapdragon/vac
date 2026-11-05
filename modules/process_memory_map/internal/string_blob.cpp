// @binary: 8d88e017
#include "core/vac_util.hpp"
#include "crt/intrinsics.hpp"
#include "internal/report_builder.hpp"

namespace vac::workers::process_memory_map
{

namespace
{

constexpr u32 k_cubStringStorage = 0x4000;
constexpr i32 k_cMaxStrings = 500;

// @orig: 8B 11 33 C0 56
i32 FindString( const StringTable_t &table, u32 unHash ) noexcept
{
	for ( i32 iEntry = 0; iEntry < table.m_cEntries; ++iEntry )
	{
		if ( table.m_pEntries[iEntry].m_unHash == unHash )
			return iEntry;
	}
	return -1;
}

// @orig: 83 EC ? 55 8B E9
void SortStrings( StringTable_t &table ) noexcept
{
	for ( i32 iEntry = 0; iEntry < table.m_cEntries; ++iEntry )
	{
		for ( i32 iOther = iEntry + 1; iOther < table.m_cEntries; ++iOther )
		{
			StringEntry_t &entry = table.m_pEntries[iEntry];
			StringEntry_t &other = table.m_pEntries[iOther];
			if ( entry.m_cUses < other.m_cUses || ( entry.m_cUses == other.m_cUses && entry.m_nRank < other.m_nRank ) )
			{
				const StringEntry_t temporary = entry;
				entry = other;
				other = temporary;
			}
		}
	}
}

// @orig: 8B 44 24 ? 53 55
bool EmitString( const StringTable_t &table, i32 iEntry, char **ppchOutput, i32 *pcubLeft ) noexcept
{
	if ( iEntry < 0 || iEntry >= table.m_cEntries )
		return false;

	const StringEntry_t &entry = table.m_pEntries[iEntry];
	if ( !entry.m_pszText )
		return false;
	if ( entry.m_cchText >= *pcubLeft )
		return false;

	*pcubLeft = *pcubLeft - entry.m_cchText - 1;
	memcpy( *ppchOutput, entry.m_pszText, entry.m_cchText + 1 );
	*ppchOutput += entry.m_cchText + 1;
	return true;
}

// @note / sapdragon: ranks a string by the most used shorter string that shares its first 8 chars
// @orig: 83 EC ? 56 57 8B F9
void RankStrings( StringTable_t &table ) noexcept
{
	for ( i32 iEntry = 0; iEntry < table.m_cEntries; ++iEntry )
	{
		StringEntry_t &entry = table.m_pEntries[iEntry];
		if ( !entry.m_pszText )
			continue;

		for ( i32 iOther = 0; iOther < table.m_cEntries; ++iOther )
		{
			const StringEntry_t &other = table.m_pEntries[iOther];
			if ( !other.m_pszText || iOther == iEntry || other.m_cchText >= entry.m_cchText ||
			     other.m_cUses <= entry.m_nRank || other.m_cchText < 0 )
				continue;

			i32 cchShared = 0;
			i32 iChar = 0;
			do
			{
				if ( entry.m_pszText[iChar] != other.m_pszText[iChar] )
					break;
				++cchShared;
				++iChar;
			} while ( iChar <= other.m_cchText );

			if ( cchShared >= 8 )
				entry.m_nRank = other.m_cUses;
		}
	}
}

// @orig: 56 8B F1 8B 56
void GrowU32Vector( U32Vector_t &vector ) noexcept
{
	if ( static_cast<i32>( vector.m_cCapacity ) == vector.m_c )
	{
		vector.m_cCapacity += 128;
		vector.m_prgun = static_cast<u32 *>( ResizeOrAlloc( vector.m_prgun, vector.m_cCapacity * sizeof( u32 ) ) );
	}
}

} // namespace

// @orig: 56 57 8B F9 E8
void PushU32( U32Vector_t &vector, u32 unValue ) noexcept
{
	GrowU32Vector( vector );
	vector.m_prgun[vector.m_c++] = unValue;
}

// @orig: 56 8B F1 B9
void InitStringTable( StringTable_t &table ) noexcept
{
	table.m_pchStorage = static_cast<char *>( util::HeapAlloc( k_cubStringStorage ) );
	table.m_pchWrite = table.m_pchStorage;
	table.m_pEntries = static_cast<StringEntry_t *>( util::HeapAlloc( k_cMaxStrings * sizeof( StringEntry_t ) ) );
	table.m_cubUsed = 0;
	table.m_cEntries = 0;
}

// @orig: 53 8B 5C 24 ? 33 C0
void AddString( StringTable_t &table, u32 unHash, const char *pszText, i32 cchText ) noexcept
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
	entry.m_cchText = cchText;
	entry.m_bEmitted = false;
	entry.m_nRank = 0;
	if ( pszText && cchText + table.m_cubUsed + 1 < static_cast<i32>( k_cubStringStorage ) )
	{
		memcpy( table.m_pchWrite, pszText, cchText );
		table.m_pchWrite[cchText] = 0;
		entry.m_pszText = table.m_pchWrite;
		table.m_pchWrite += cchText + 1;
		table.m_cubUsed += cchText + 1;
	}
	++table.m_cEntries;
}

// @note / sapdragon: directories go out from least to most used, each after the base names first seen with it
// @orig: 83 EC ? 53 55 8B D9
i32 PackStrings( StringTable_t &baseNames, StringTable_t &directories, const U32Vector_t &directoryHashes,
                 const U32Vector_t &baseNameHashes, U32Vector_t &stringEnds, char *pchOutput ) noexcept
{
	const i32 cubOutput = sizeof( ReportBuilder_t::m_rgchStrings );
	i32 cubLeft = cubOutput;
	if ( !directories.m_cEntries )
		return 0;

	RankStrings( directories );
	SortStrings( directories );

	for ( i32 iDirectory = directories.m_cEntries - 1; iDirectory >= 0; --iDirectory )
	{
		for ( i32 iPair = 0; iPair < directoryHashes.m_c; ++iPair )
		{
			if ( FindString( directories, directoryHashes.m_prgun[iPair] ) != iDirectory )
				continue;

			// @note / sapdragon: a full base name table gives -1 and reads the entry before the array. emit refuses it
			// after that, so it is only a stray read
			const i32 iBaseName = FindString( baseNames, baseNameHashes.m_prgun[iPair] );
			if ( baseNames.m_pEntries[iBaseName].m_bEmitted || !baseNames.m_pEntries[iBaseName].m_pszText )
				continue;

			if ( EmitString( baseNames, iBaseName, &pchOutput, &cubLeft ) )
				PushU32( stringEnds, cubOutput - cubLeft );
			if ( iBaseName >= 0 && iBaseName < baseNames.m_cEntries )
				baseNames.m_pEntries[iBaseName].m_bEmitted = true;
			if ( cubLeft < 0 )
				return cubOutput - cubLeft;
		}

		if ( EmitString( directories, iDirectory, &pchOutput, &cubLeft ) )
			PushU32( stringEnds, cubOutput - cubLeft );
		if ( iDirectory < directories.m_cEntries )
			directories.m_pEntries[iDirectory].m_bEmitted = true;
		if ( cubLeft < 0 )
			break;
	}
	return cubOutput - cubLeft;
}

} // namespace vac::workers::process_memory_map
