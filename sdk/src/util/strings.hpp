// @binary: 42878040
#pragma once

#include "core/types.hpp"
#include "crt/intrinsics.hpp"

namespace vac::util
{

// @note / sapdragon: the null check is ours, the original would fault on null
// @orig: 33 C0 38 01 74
inline u32 StrLenA( const char *pszText ) noexcept
{
	if ( !pszText )
		return 0;
	u32 cChars = 0;
	while ( pszText[cChars] )
		++cChars;
	return cChars;
}

inline u32 StrLenW( const wchar_t *pwszText ) noexcept
{
	if ( !pwszText )
		return 0;
	u32 cChars = 0;
	while ( pwszText[cChars] )
		++cChars;
	return cChars;
}

inline bool EqualA( const char *pszA, const char *pszB ) noexcept
{
	while ( *pszA == *pszB )
	{
		if ( !*pszA )
			return true;
		++pszA;
		++pszB;
	}
	return false;
}

inline const char *BasenameA( const char *pszPath ) noexcept
{
	const char *pszBase = pszPath;
	for ( const char *pszChar = pszPath; *pszChar; ++pszChar )
	{
		if ( *pszChar == '\\' || *pszChar == '/' )
			pszBase = pszChar + 1;
	}
	return pszBase;
}

inline void CopyA( char *pszDst, const char *pszSrc, u32 cubDst ) noexcept
{
	if ( !cubDst )
		return;

	u32 iChar = 0;
	if ( pszSrc )
	{
		for ( ; iChar + 1 < cubDst && pszSrc[iChar]; ++iChar )
			pszDst[iChar] = pszSrc[iChar];
	}
	pszDst[iChar] = 0;
}

inline u32 Read32( const void *pData ) noexcept
{
	u32 unValue = 0;
	memcpy( &unValue, pData, sizeof( unValue ) );
	return unValue;
}

inline u64 Read64( const void *pData ) noexcept
{
	u64 ulValue = 0;
	memcpy( &ulValue, pData, sizeof( ulValue ) );
	return ulValue;
}

inline void Write16( void *pData, u16 unValue ) noexcept
{
	memcpy( pData, &unValue, sizeof( unValue ) );
}

constexpr u32 AlignUp( u32 unValue, u32 unAlignment ) noexcept
{
	if ( !unAlignment )
		return unValue;
	const u32 unRemainder = unValue % unAlignment;
	return unRemainder ? unValue + unAlignment - unRemainder : unValue;
}

} // namespace vac::util
