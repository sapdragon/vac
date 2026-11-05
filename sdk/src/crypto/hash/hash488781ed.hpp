// @binary: 9b85c913
#pragma once

#include "core/types.hpp"

namespace vac::crypto::hash
{

struct Hash488781ED_t
{
	u32 m_unState = 0;

	constexpr Hash488781ED_t() = default;
	constexpr explicit Hash488781ED_t( u32 unSeed ) noexcept : m_unState{ unSeed } {}

	constexpr Hash488781ED_t &Update( const u8 *pubData, usize cubData ) noexcept
	{
		for ( usize ib = 0; ib < cubData; ++ib )
		{
			m_unState ^= u32( pubData[ib] ) << 24;
			for ( u32 iBit = 0; iBit < 8; ++iBit )
				m_unState = ( m_unState & 0x80000000u ) ? ( ( m_unState << 1 ) ^ 0x488781EDu ) : ( m_unState << 1 );
		}
		return *this;
	}

	[[nodiscard]] constexpr u32 Value() const noexcept { return m_unState; }

	// @orig: 55 56 8B 74 24 ? 8B E9
	[[nodiscard]] static constexpr u32 Of( const u8 *pubData, usize cubData, u32 unSeed = 0 ) noexcept
	{
		return Hash488781ED_t{ unSeed }.Update( pubData, cubData ).Value();
	}
};

} // namespace vac::crypto::hash
