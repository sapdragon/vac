// @binary: 9b85c913
#pragma once

#include "core/types.hpp"
#include "crypto/ice/internal/round.hpp"

namespace vac::crypto::ice
{

inline constexpr usize k_cubBlock = 8;
inline constexpr usize k_cubKey = 8;
inline constexpr usize k_cRounds = 16;

struct IceKey_t
{
	i32 m_nSize;
	i32 m_cRounds;
	u32 m_rgrgunSchedule[k_cRounds][3];

	// @orig: 83 EC ? 53 55 56 57
	constexpr explicit IceKey_t( const u8 ( &rgubKey )[k_cubKey] ) noexcept
	    : m_nSize{ 1 }, m_cRounds{ static_cast<i32>( k_cRounds ) }, m_rgrgunSchedule{}
	{
		u16 rgunWords[4]{};
		for ( usize iWord = 0; iWord < 4; ++iWord )
		{
			rgunWords[3 - iWord] = static_cast<u16>( ( static_cast<u16>( rgubKey[iWord * 2] ) << 8 ) |
			                                         static_cast<u16>( rgubKey[iWord * 2 + 1] ) );
		}
		BuildSchedule( 0, &detail::k_rgunKeyRot[0], rgunWords );
		BuildSchedule( 8, &detail::k_rgunKeyRot[8], rgunWords );
	}

private:
	// @orig: 83 EC ? 53 55 56 33 F6
	constexpr void BuildSchedule( usize iRound, const u32 *punKeyRot, u16 ( &rgunWords )[4] ) noexcept
	{
		for ( usize iStep = 0; iStep < 8; ++iStep )
		{
			const u32 unRotation = punKeyRot[iStep];
			u32( &rgunSubkey )[3] = m_rgrgunSchedule[iRound + iStep];
			rgunSubkey[0] = rgunSubkey[1] = rgunSubkey[2] = 0;

			for ( usize iBit = 0; iBit < 15; ++iBit )
			{
				u32 &unTarget = rgunSubkey[iBit % 3];
				for ( usize iWord = 0; iWord < 4; ++iWord )
				{
					u16 &unWord = rgunWords[( unRotation + iWord ) & 3];
					const u32 unBit = static_cast<u32>( unWord ) & 1;
					unTarget = ( unTarget << 1 ) | unBit;
					unWord = static_cast<u16>( ( unWord >> 1 ) | ( ( unBit ^ 1 ) << 15 ) );
				}
			}
		}
	}
};
static_assert( sizeof( IceKey_t ) == 200, "IceKey_t is two ints and sixteen subkeys" );

namespace detail
{

constexpr void ReadBlockBe( const u8 *pubIn, u32 &unLeft, u32 &unRight ) noexcept
{
	unLeft = ( u32( pubIn[0] ) << 24 ) | ( u32( pubIn[1] ) << 16 ) | ( u32( pubIn[2] ) << 8 ) | u32( pubIn[3] );
	unRight = ( u32( pubIn[4] ) << 24 ) | ( u32( pubIn[5] ) << 16 ) | ( u32( pubIn[6] ) << 8 ) | u32( pubIn[7] );
}

constexpr void WriteBlockBe( u8 *pubOut, u32 unRight, u32 unLeft ) noexcept
{
	for ( usize ib = 0; ib < 4; ++ib )
	{
		pubOut[3 - ib] = static_cast<u8>( unRight );
		unRight >>= 8;
		pubOut[7 - ib] = static_cast<u8>( unLeft );
		unLeft >>= 8;
	}
}

} // namespace detail

// @orig: 8B 54 24 ? 53 55 8B E9 0F B6 1A
constexpr void EncryptBlock( const IceKey_t &key, const u8 *pubIn, u8 *pubOut ) noexcept
{
	u32 unLeft = 0;
	u32 unRight = 0;
	detail::ReadBlockBe( pubIn, unLeft, unRight );
	for ( usize iRound = 0; iRound < k_cRounds; iRound += 2 )
	{
		unLeft ^= detail::FRound( unRight, key.m_rgrgunSchedule[iRound] );
		unRight ^= detail::FRound( unLeft, key.m_rgrgunSchedule[iRound + 1] );
	}
	detail::WriteBlockBe( pubOut, unRight, unLeft );
}

// @orig: 55 8B EC 8B 55
constexpr void DecryptBlock( const IceKey_t &key, const u8 *pubIn, u8 *pubOut ) noexcept
{
	u32 unLeft = 0;
	u32 unRight = 0;
	detail::ReadBlockBe( pubIn, unLeft, unRight );
	for ( usize iRound = k_cRounds; iRound > 0; iRound -= 2 )
	{
		unLeft ^= detail::FRound( unRight, key.m_rgrgunSchedule[iRound - 1] );
		unRight ^= detail::FRound( unLeft, key.m_rgrgunSchedule[iRound - 2] );
	}
	detail::WriteBlockBe( pubOut, unRight, unLeft );
}

inline void EncryptBlock( const u8 ( &rgubKey )[k_cubKey], const u8 *pubIn, u8 *pubOut ) noexcept
{
	EncryptBlock( IceKey_t{ rgubKey }, pubIn, pubOut );
}

inline void DecryptBlock( const u8 ( &rgubKey )[k_cubKey], const u8 *pubIn, u8 *pubOut ) noexcept
{
	DecryptBlock( IceKey_t{ rgubKey }, pubIn, pubOut );
}

inline void EncryptBlock( const u8 *pubKey, const u8 *pubIn, u8 *pubOut ) noexcept
{
	u8 rgubKey[k_cubKey]{};
	for ( usize ib = 0; ib < k_cubKey; ++ib )
		rgubKey[ib] = pubKey[ib];
	EncryptBlock( IceKey_t{ rgubKey }, pubIn, pubOut );
}

inline void DecryptBlock( const u8 *pubKey, const u8 *pubIn, u8 *pubOut ) noexcept
{
	u8 rgubKey[k_cubKey]{};
	for ( usize ib = 0; ib < k_cubKey; ++ib )
		rgubKey[ib] = pubKey[ib];
	DecryptBlock( IceKey_t{ rgubKey }, pubIn, pubOut );
}

void EncryptBuffer( const IceKey_t &key, const u8 *pubIn, usize cubData, u8 *pubOut ) noexcept;
void DecryptBuffer( const IceKey_t &key, const u8 *pubIn, usize cubData, u8 *pubOut ) noexcept;
void EncryptBuffer( const u8 ( &rgubKey )[k_cubKey], const u8 *pubIn, usize cubData, u8 *pubOut ) noexcept;
void DecryptBuffer( const u8 ( &rgubKey )[k_cubKey], const u8 *pubIn, usize cubData, u8 *pubOut ) noexcept;
void EncryptBuffer( const u8 *pubKey, const u8 *pubIn, usize cubData, u8 *pubOut ) noexcept;
void DecryptBuffer( const u8 *pubKey, const u8 *pubIn, usize cubData, u8 *pubOut ) noexcept;

} // namespace vac::crypto::ice
