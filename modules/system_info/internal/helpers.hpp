// @binary: a07ed54b
#pragma once

#include "bootstrap/imports.hpp"
#include "crt/intrinsics.hpp"

// @note / sapdragon: these use the linked kernel32 on purpose, the workers free memory after the import table
// is gone

namespace vac::workers::system_info
{

// @orig: a07ed54b:0x100064C6 (no unique signature)
inline void *HeapAllocate( SIZE_T cubSize ) noexcept
{
	return HeapAlloc( GetProcessHeap(), 0, cubSize );
}

// @orig: a07ed54b:0x100064D7 (no unique signature)
inline void HeapRelease( void *pMemory ) noexcept
{
	HeapFree( GetProcessHeap(), 0, pMemory );
}

// @orig: 52 85 C9 74
inline void *HeapResize( void *pMemory, SIZE_T cubSize ) noexcept
{
	if ( pMemory )
		return HeapReAlloc( GetProcessHeap(), 0, pMemory, cubSize );
	return HeapAlloc( GetProcessHeap(), 0, cubSize );
}

// @orig: 56 57 8B FA 33 F6
inline i32 CompareBounded( const char *pszA, const char *pszB ) noexcept
{
	u32 iChar = 0;
	for ( ;; )
	{
		const u8 unChar = static_cast<u8>( pszA[iChar] );
		if ( !unChar || unChar != static_cast<u8>( pszB[iChar] ) )
			return unChar - static_cast<u8>( pszB[iChar] );
		if ( ++iChar >= 0xFFFF )
			return 0;
	}
}

// @orig: 53 55 56 57 8B EA
inline i32 CompareBoundedNoCase( const char *pszA, const char *pszB ) noexcept
{
	u32 cCompared = 0;
	for ( ;; )
	{
		const char chA = *pszA++;
		const char chB = *pszB++;
		if ( chA == chB )
		{
			if ( !chA )
				return 0;
		}
		else
		{
			const char chLowerB = static_cast<u8>( chB - 'A' ) > 0x19 ? chB : static_cast<char>( chB | 0x20 );
			const char chLowerA = static_cast<u8>( chA - 'A' ) > 0x19 ? chA : static_cast<char>( chA | 0x20 );
			if ( chLowerA != chLowerB )
				return 1;
		}
		if ( ++cCompared >= 0xFFFF )
			return 0;
	}
}

// @orig: 53 56 57 8B 7C 24 ? 8B F2
inline wchar_t *CopyWideClearRest( wchar_t *pwszDst, const wchar_t *pwszSrc, u32 cChars ) noexcept
{
	// @note / sapdragon: copies cChars no matter how long the source is, then clears past its end
	memcpy( pwszDst, pwszSrc, 2 * cChars );
	const u32 cSource = static_cast<u32>( lstrlenW( pwszSrc ) );
	if ( cChars > cSource )
		memset( pwszDst + cSource, 0, 2 * ( cChars - cSource ) );
	return pwszDst;
}

} // namespace vac::workers::system_info
