// @binary: 9b85c913
#pragma once

#include "core/types.hpp"
#include "crypto/ice/internal/sbox.hpp"

namespace vac::crypto::ice::detail
{

constexpr u32 RotateRight( u32 unValue, u32 cBits ) noexcept
{
	return ( unValue >> cBits ) | ( unValue << ( 32 - cBits ) );
}

// @orig: 53 55 56 8B F1 BD
constexpr u32 FRound( u32 unHalf, const u32 ( &rgunSubkey )[3] ) noexcept
{
	const u32 unLeft = ( ( unHalf >> 16 ) & 0x3FF ) | ( RotateRight( unHalf, 14 ) & 0xFFC00 );
	const u32 unRight = ( unHalf & 0x3FF ) | ( ( unHalf & 0x3FF00 ) << 2 );

	const u32 unMask = rgunSubkey[2] & ( unLeft ^ unRight );
	const u32 unMixedLeft = unLeft ^ unMask ^ rgunSubkey[0];
	const u32 unMixedRight = unRight ^ unMask ^ rgunSubkey[1];

	return k_Sbox0.m_rgunEntries[unMixedLeft >> 10] ^ k_Sbox1.m_rgunEntries[unMixedLeft & 0x3FF] ^
	       k_Sbox2.m_rgunEntries[unMixedRight >> 10] ^ k_Sbox3.m_rgunEntries[unMixedRight & 0x3FF];
}

} // namespace vac::crypto::ice::detail
