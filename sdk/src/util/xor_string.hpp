#pragma once

#include "core/types.hpp"

namespace vac::util
{

template <u8 unKey, typename Char_t, usize cChars>
struct XorString_t
{
	Char_t m_rgChars[cChars];

	consteval explicit XorString_t( const Char_t ( &rgChars )[cChars] ) : m_rgChars{}
	{
		for ( usize iChar = 0; iChar + 1 < cChars; ++iChar )
			m_rgChars[iChar] = static_cast<Char_t>( rgChars[iChar] ^ unKey );
	}

	void Decode() noexcept
	{
		for ( Char_t *pChar = m_rgChars; *pChar; ++pChar )
			*pChar = static_cast<Char_t>( *pChar ^ unKey );
	}

	[[nodiscard]] const Char_t *Get() const noexcept { return m_rgChars; }
};

template <u8 unKey, usize cChars>
consteval auto MakeXorString( const char ( &rgChars )[cChars] )
{
	return XorString_t<unKey, char, cChars>{ rgChars };
}

template <u8 unKey, usize cChars>
consteval auto MakeXorString( const wchar_t ( &rgChars )[cChars] )
{
	return XorString_t<unKey, wchar_t, cChars>{ rgChars };
}

} // namespace vac::util
