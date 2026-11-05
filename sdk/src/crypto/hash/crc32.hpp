// @binary: 9b85c913
#pragma once

#include "core/types.hpp"

namespace vac::crypto::hash
{

namespace detail
{

struct Crc32Table_t
{
	u32 m_rgunEntries[256];
};

constexpr Crc32Table_t MakeCrc32Table() noexcept
{
	Crc32Table_t table{};
	for ( u32 iEntry = 0; iEntry < 256; ++iEntry )
	{
		u32 unValue = iEntry;
		for ( u32 iBit = 0; iBit < 8; ++iBit )
			unValue = ( unValue & 1 ) ? ( ( unValue >> 1 ) ^ 0xEDB88320u ) : ( unValue >> 1 );
		table.m_rgunEntries[iEntry] = unValue;
	}
	return table;
}

inline constexpr Crc32Table_t k_Crc32Table = MakeCrc32Table();

} // namespace detail

struct Crc32_t
{
	u32 m_unState = 0xFFFFFFFFu;

	constexpr Crc32_t() = default;
	constexpr explicit Crc32_t( u32 unInitial ) noexcept : m_unState{ unInitial } {}

	constexpr Crc32_t &Update( const u8 *pubData, usize cubData ) noexcept
	{
		for ( usize ib = 0; ib < cubData; ++ib )
			m_unState = detail::k_Crc32Table.m_rgunEntries[( m_unState ^ pubData[ib] ) & 0xFFu] ^ ( m_unState >> 8 );
		return *this;
	}

	[[nodiscard]] constexpr u32 Value() const noexcept { return ~m_unState; }

	// @orig: 53 55 8B E9 56
	[[nodiscard]] static constexpr u32 Of( const u8 *pubData, usize cubData ) noexcept
	{
		return Crc32_t{}.Update( pubData, cubData ).Value();
	}
};

} // namespace vac::crypto::hash
