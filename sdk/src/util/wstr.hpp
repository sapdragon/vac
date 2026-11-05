// @binary: 42878040
#pragma once

#include "core/types.hpp"

namespace vac::util::wstr
{

inline u32 Length( const wchar_t *pwszText ) noexcept
{
	if ( !pwszText )
		return 0;
	u32 cChars = 0;
	while ( pwszText[cChars] )
		++cChars;
	return cChars;
}

inline void Copy( wchar_t *pwszDst, const wchar_t *pwszSrc, u32 cMaxChars ) noexcept
{
	if ( !pwszDst || !cMaxChars )
		return;
	if ( !pwszSrc )
	{
		pwszDst[0] = 0;
		return;
	}
	u32 iChar = 0;
	while ( iChar + 1 < cMaxChars && pwszSrc[iChar] )
	{
		pwszDst[iChar] = pwszSrc[iChar];
		++iChar;
	}
	pwszDst[iChar] = 0;
}

inline void Cat( wchar_t *pwszDst, const wchar_t *pwszSrc, u32 cMaxChars ) noexcept
{
	if ( !pwszDst || !pwszSrc || !cMaxChars )
		return;
	u32 iChar = 0;
	while ( iChar < cMaxChars && pwszDst[iChar] )
		++iChar;
	while ( iChar + 1 < cMaxChars && *pwszSrc )
		pwszDst[iChar++] = *pwszSrc++;
	pwszDst[iChar] = 0;
}

inline bool PrefixEqualI( const wchar_t *pwszA, const wchar_t *pwszB, u32 cChars ) noexcept
{
	for ( u32 iChar = 0; iChar < cChars; ++iChar )
	{
		wchar_t wchA = pwszA[iChar];
		wchar_t wchB = pwszB[iChar];
		if ( wchA >= L'A' && wchA <= L'Z' )
			wchA = static_cast<wchar_t>( wchA + 0x20 );
		if ( wchB >= L'A' && wchB <= L'Z' )
			wchB = static_cast<wchar_t>( wchB + 0x20 );
		if ( wchA != wchB )
			return false;
		if ( !wchA )
			return true;
	}
	return true;
}

// @orig: 56 8B F1 56 FF 15
inline const wchar_t *BaseName( const wchar_t *pwszPath ) noexcept
{
	// @note / sapdragon: never looks at the first char, so "\name" comes back whole. valve's quirk
	i32 iChar = static_cast<i32>( Length( pwszPath ) ) - 1;
	if ( iChar <= 0 )
		return pwszPath;
	const wchar_t *pwszChar = pwszPath + iChar;
	while ( *pwszChar != L'\\' )
	{
		if ( --iChar <= 0 )
			return pwszPath;
		--pwszChar;
	}
	return pwszChar + 1;
}

} // namespace vac::util::wstr
