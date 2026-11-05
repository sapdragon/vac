// @binary: 9b85c913
#pragma once

#include "core/types.hpp"
#include "crypto/ice/internal/constants.hpp"

// @note / sapdragon: the original builds its s-boxes on first use, here they are compile-time data

namespace vac::crypto::ice::detail
{

// @orig: 53 56 57 8B FA
constexpr u32 GfMult( u32 unA, u32 unB, u32 unModulus ) noexcept
{
	u32 unResult = 0;
	while ( unB )
	{
		if ( unB & 1 )
			unResult ^= unA;
		unB >>= 1;
		unA <<= 1;
		if ( unA >= 0x100 )
			unA ^= unModulus;
	}
	return unResult;
}

// @orig: 56 8B F1 57 8B FA
constexpr u32 GfExp7( u32 unBase, u32 unModulus ) noexcept
{
	if ( !unBase )
		return 0;
	u32 unValue = GfMult( unBase, unBase, unModulus );
	unValue = GfMult( unBase, unValue, unModulus );
	unValue = GfMult( unValue, unValue, unModulus );
	return GfMult( unBase, unValue, unModulus );
}

// @orig: 33 C0 BA
constexpr u32 Permute32( u32 unValue ) noexcept
{
	u32 unResult = 0;
	for ( u32 iBit = 0; iBit < 32; ++iBit )
	{
		if ( unValue & 1 )
			unResult |= k_rgunPbox[iBit];
		unValue >>= 1;
		if ( !unValue )
			break;
	}
	return unResult;
}

struct Sbox_t
{
	u32 m_rgunEntries[1024];
};

// @orig: 53 56 57 33 DB
template <usize iBox>
constexpr Sbox_t MakeSbox() noexcept
{
	Sbox_t box{};
	for ( usize iEntry = 0; iEntry < 1024; ++iEntry )
	{
		const u32 iColumn = static_cast<u32>( ( iEntry >> 1 ) & 0xFF );
		const u32 iRow = static_cast<u32>( ( iEntry & 1 ) | ( ( iEntry >> 8 ) & 2 ) );
		const u32 unInput = iColumn ^ k_rgrgunSxor[iBox][iRow];
		const u32 unExponent = GfExp7( unInput, k_rgrgunSmod[iBox][iRow] );
		const u32 cShift = static_cast<u32>( ( 3 - iBox ) * 8 );
		box.m_rgunEntries[iEntry] = Permute32( unExponent << cShift );
	}
	return box;
}

inline constexpr Sbox_t k_Sbox0 = MakeSbox<0>();
inline constexpr Sbox_t k_Sbox1 = MakeSbox<1>();
inline constexpr Sbox_t k_Sbox2 = MakeSbox<2>();
inline constexpr Sbox_t k_Sbox3 = MakeSbox<3>();

} // namespace vac::crypto::ice::detail
