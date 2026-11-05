#pragma once

#include "core/types.hpp"

// @note / sapdragon: valve keeps these on the stack rotated right by three, rotates them back after bootstrap

namespace vac::workers::boot_config
{

constexpr char Ror3( char chValue ) noexcept
{
	const u8 ubValue = static_cast<u8>( chValue );
	return static_cast<char>( static_cast<u8>( ( ubValue >> 3 ) | ( ubValue << 5 ) ) );
}

constexpr char Rol3( char chValue ) noexcept
{
	const u8 ubValue = static_cast<u8>( chValue );
	return static_cast<char>( static_cast<u8>( ( ubValue << 3 ) | ( ubValue >> 5 ) ) );
}

template <usize cChars>
struct Rol3String_t
{
	char m_rgChars[cChars];

	consteval explicit Rol3String_t( const char ( &rgChars )[cChars] ) : m_rgChars{}
	{
		for ( usize iChar = 0; iChar + 1 < cChars; ++iChar )
			m_rgChars[iChar] = Ror3( rgChars[iChar] );
	}

	void Decode() noexcept
	{
		for ( char *pChar = m_rgChars; *pChar; ++pChar )
			*pChar = Rol3( *pChar );
	}

	void DecodeAll() noexcept
	{
		for ( char &chValue : m_rgChars )
			chValue = Rol3( chValue );
	}

	[[nodiscard]] char *Get() noexcept { return m_rgChars; }
};

template <usize cChars>
consteval auto MakeRol3String( const char ( &rgChars )[cChars] )
{
	return Rol3String_t<cChars>{ rgChars };
}

} // namespace vac::workers::boot_config
