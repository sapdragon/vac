// @binary: 42878040
#pragma once

#include "core/types.hpp"

namespace vac::util::hashing
{

inline constexpr u32 k_unHashSeed = 0x45D71892u;

constexpr u32 Djb2LowerSized( u32 unSeed, const u8 *pubData, u32 cubData ) noexcept
{
	u32 unHash = unSeed;
	for ( u32 ib = 0; ib < cubData; ++ib )
		unHash = ( static_cast<u8>( pubData[ib] ) | 0x20u ) + 33u * unHash;
	return unHash;
}

constexpr u32 Djb2LowerNul( u32 unSeed, const char *pszText ) noexcept
{
	if ( !pszText )
		return unSeed;
	u32 unHash = unSeed;
	while ( *pszText )
		unHash = ( static_cast<u8>( *pszText++ ) | 0x20u ) + 33u * unHash;
	return unHash;
}

constexpr u32 PathHash( const char *pszText ) noexcept
{
	return Djb2LowerNul( k_unHashSeed, pszText );
}

// @orig: B8 ? ? ? ? 85 D2
constexpr u32 PathHashBytes( const u8 *pubData, u32 cubData ) noexcept
{
	return Djb2LowerSized( k_unHashSeed, pubData, cubData );
}

// @note / sapdragon: zero for empty input comes from the service_lookup rebuild, PathHashBytes gives the seed
constexpr u32 ServiceNameHash( const char *pszText, u32 cchText ) noexcept
{
	if ( cchText == 0 || pszText == nullptr )
		return 0;
	u32 unHash = k_unHashSeed;
	for ( u32 iChar = 0; iChar < cchText; ++iChar )
		unHash = ( static_cast<u8>( pszText[iChar] ) | 0x20u ) + 33u * unHash;
	return unHash;
}

constexpr u32 ServiceNameHash( const char *pszText ) noexcept
{
	if ( !pszText )
		return 0;
	u32 cchText = 0;
	while ( pszText[cchText] )
		++cchText;
	return ServiceNameHash( pszText, cchText );
}

} // namespace vac::util::hashing
