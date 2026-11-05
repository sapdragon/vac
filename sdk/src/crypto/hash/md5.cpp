// @binary: 42878040
#include "crypto/hash/md5.hpp"
#include "crt/intrinsics.hpp"

namespace vac::crypto::hash
{

namespace
{

inline u32 RotateLeft( u32 unValue, u32 cBits ) noexcept
{
	return ( unValue << cBits ) | ( unValue >> ( 32 - cBits ) );
}

inline void RoundF( u32 &unA, u32 unB, u32 unC, u32 unD, u32 unWord, u32 cBits, u32 unConstant ) noexcept
{
	unA = unB + RotateLeft( unA + ( ( unB & unC ) | ( ~unB & unD ) ) + unWord + unConstant, cBits );
}

inline void RoundG( u32 &unA, u32 unB, u32 unC, u32 unD, u32 unWord, u32 cBits, u32 unConstant ) noexcept
{
	unA = unB + RotateLeft( unA + ( ( unB & unD ) | ( unC & ~unD ) ) + unWord + unConstant, cBits );
}

inline void RoundH( u32 &unA, u32 unB, u32 unC, u32 unD, u32 unWord, u32 cBits, u32 unConstant ) noexcept
{
	unA = unB + RotateLeft( unA + ( unB ^ unC ^ unD ) + unWord + unConstant, cBits );
}

inline void RoundI( u32 &unA, u32 unB, u32 unC, u32 unD, u32 unWord, u32 cBits, u32 unConstant ) noexcept
{
	unA = unB + RotateLeft( unA + ( unC ^ ( unB | ~unD ) ) + unWord + unConstant, cBits );
}

} // namespace

// @orig: 83 EC ? 53 8B 59
void Md5_t::Transform( const u8 *pubBlock ) noexcept
{
	u32 rgunBlock[16];
	for ( u32 iWord = 0; iWord < 16; ++iWord )
	{
		rgunBlock[iWord] = u32( pubBlock[iWord * 4] ) | ( u32( pubBlock[iWord * 4 + 1] ) << 8 ) |
		                   ( u32( pubBlock[iWord * 4 + 2] ) << 16 ) | ( u32( pubBlock[iWord * 4 + 3] ) << 24 );
	}

	u32 unA = m_rgunState[0];
	u32 unB = m_rgunState[1];
	u32 unC = m_rgunState[2];
	u32 unD = m_rgunState[3];

	RoundF( unA, unB, unC, unD, rgunBlock[0], 7, 0xD76AA478u );
	RoundF( unD, unA, unB, unC, rgunBlock[1], 12, 0xE8C7B756u );
	RoundF( unC, unD, unA, unB, rgunBlock[2], 17, 0x242070DBu );
	RoundF( unB, unC, unD, unA, rgunBlock[3], 22, 0xC1BDCEEEu );
	RoundF( unA, unB, unC, unD, rgunBlock[4], 7, 0xF57C0FAFu );
	RoundF( unD, unA, unB, unC, rgunBlock[5], 12, 0x4787C62Au );
	RoundF( unC, unD, unA, unB, rgunBlock[6], 17, 0xA8304613u );
	RoundF( unB, unC, unD, unA, rgunBlock[7], 22, 0xFD469501u );
	RoundF( unA, unB, unC, unD, rgunBlock[8], 7, 0x698098D8u );
	RoundF( unD, unA, unB, unC, rgunBlock[9], 12, 0x8B44F7AFu );
	RoundF( unC, unD, unA, unB, rgunBlock[10], 17, 0xFFFF5BB1u );
	RoundF( unB, unC, unD, unA, rgunBlock[11], 22, 0x895CD7BEu );
	RoundF( unA, unB, unC, unD, rgunBlock[12], 7, 0x6B901122u );
	RoundF( unD, unA, unB, unC, rgunBlock[13], 12, 0xFD987193u );
	RoundF( unC, unD, unA, unB, rgunBlock[14], 17, 0xA679438Eu );
	RoundF( unB, unC, unD, unA, rgunBlock[15], 22, 0x49B40821u );

	RoundG( unA, unB, unC, unD, rgunBlock[1], 5, 0xF61E2562u );
	RoundG( unD, unA, unB, unC, rgunBlock[6], 9, 0xC040B340u );
	RoundG( unC, unD, unA, unB, rgunBlock[11], 14, 0x265E5A51u );
	RoundG( unB, unC, unD, unA, rgunBlock[0], 20, 0xE9B6C7AAu );
	RoundG( unA, unB, unC, unD, rgunBlock[5], 5, 0xD62F105Du );
	RoundG( unD, unA, unB, unC, rgunBlock[10], 9, 0x02441453u );
	RoundG( unC, unD, unA, unB, rgunBlock[15], 14, 0xD8A1E681u );
	RoundG( unB, unC, unD, unA, rgunBlock[4], 20, 0xE7D3FBC8u );
	RoundG( unA, unB, unC, unD, rgunBlock[9], 5, 0x21E1CDE6u );
	RoundG( unD, unA, unB, unC, rgunBlock[14], 9, 0xC33707D6u );
	RoundG( unC, unD, unA, unB, rgunBlock[3], 14, 0xF4D50D87u );
	RoundG( unB, unC, unD, unA, rgunBlock[8], 20, 0x455A14EDu );
	RoundG( unA, unB, unC, unD, rgunBlock[13], 5, 0xA9E3E905u );
	RoundG( unD, unA, unB, unC, rgunBlock[2], 9, 0xFCEFA3F8u );
	RoundG( unC, unD, unA, unB, rgunBlock[7], 14, 0x676F02D9u );
	RoundG( unB, unC, unD, unA, rgunBlock[12], 20, 0x8D2A4C8Au );

	RoundH( unA, unB, unC, unD, rgunBlock[5], 4, 0xFFFA3942u );
	RoundH( unD, unA, unB, unC, rgunBlock[8], 11, 0x8771F681u );
	RoundH( unC, unD, unA, unB, rgunBlock[11], 16, 0x6D9D6122u );
	RoundH( unB, unC, unD, unA, rgunBlock[14], 23, 0xFDE5380Cu );
	RoundH( unA, unB, unC, unD, rgunBlock[1], 4, 0xA4BEEA44u );
	RoundH( unD, unA, unB, unC, rgunBlock[4], 11, 0x4BDECFA9u );
	RoundH( unC, unD, unA, unB, rgunBlock[7], 16, 0xF6BB4B60u );
	RoundH( unB, unC, unD, unA, rgunBlock[10], 23, 0xBEBFBC70u );
	RoundH( unA, unB, unC, unD, rgunBlock[13], 4, 0x289B7EC6u );
	RoundH( unD, unA, unB, unC, rgunBlock[0], 11, 0xEAA127FAu );
	RoundH( unC, unD, unA, unB, rgunBlock[3], 16, 0xD4EF3085u );
	RoundH( unB, unC, unD, unA, rgunBlock[6], 23, 0x04881D05u );
	RoundH( unA, unB, unC, unD, rgunBlock[9], 4, 0xD9D4D039u );
	RoundH( unD, unA, unB, unC, rgunBlock[12], 11, 0xE6DB99E5u );
	RoundH( unC, unD, unA, unB, rgunBlock[15], 16, 0x1FA27CF8u );
	RoundH( unB, unC, unD, unA, rgunBlock[2], 23, 0xC4AC5665u );

	RoundI( unA, unB, unC, unD, rgunBlock[0], 6, 0xF4292244u );
	RoundI( unD, unA, unB, unC, rgunBlock[7], 10, 0x432AFF97u );
	RoundI( unC, unD, unA, unB, rgunBlock[14], 15, 0xAB9423A7u );
	RoundI( unB, unC, unD, unA, rgunBlock[5], 21, 0xFC93A039u );
	RoundI( unA, unB, unC, unD, rgunBlock[12], 6, 0x655B59C3u );
	RoundI( unD, unA, unB, unC, rgunBlock[3], 10, 0x8F0CCC92u );
	RoundI( unC, unD, unA, unB, rgunBlock[10], 15, 0xFFEFF47Du );
	RoundI( unB, unC, unD, unA, rgunBlock[1], 21, 0x85845DD1u );
	RoundI( unA, unB, unC, unD, rgunBlock[8], 6, 0x6FA87E4Fu );
	RoundI( unD, unA, unB, unC, rgunBlock[15], 10, 0xFE2CE6E0u );
	RoundI( unC, unD, unA, unB, rgunBlock[6], 15, 0xA3014314u );
	RoundI( unB, unC, unD, unA, rgunBlock[13], 21, 0x4E0811A1u );
	RoundI( unA, unB, unC, unD, rgunBlock[4], 6, 0xF7537E82u );
	RoundI( unD, unA, unB, unC, rgunBlock[11], 10, 0xBD3AF235u );
	RoundI( unC, unD, unA, unB, rgunBlock[2], 15, 0x2AD7D2BBu );
	RoundI( unB, unC, unD, unA, rgunBlock[9], 21, 0xEB86D391u );

	m_rgunState[0] += unA;
	m_rgunState[1] += unB;
	m_rgunState[2] += unC;
	m_rgunState[3] += unD;
}

// @orig: 53 8B D9 55 56
void Md5_t::Update( const u8 *pubData, usize cubData ) noexcept
{
	u32 ibBuffer = static_cast<u32>( ( m_ulBitCount >> 3 ) & 0x3F );
	m_ulBitCount += static_cast<u64>( cubData ) << 3;

	const u32 cubPart = 64 - ibBuffer;
	usize ibData = 0;
	if ( cubData >= cubPart )
	{
		memcpy( &m_rgubBuffer[ibBuffer], pubData, cubPart );
		Transform( m_rgubBuffer );
		for ( ibData = cubPart; ibData + 63 < cubData; ibData += 64 )
			Transform( &pubData[ibData] );
		ibBuffer = 0;
	}
	if ( ibData < cubData )
		memcpy( &m_rgubBuffer[ibBuffer], &pubData[ibData], cubData - ibData );
}

// @orig: 53 55 56 8B F2
void Md5_t::Final( u8 *pubDigest ) noexcept
{
	u8 rgubLength[8];
	memcpy( rgubLength, &m_ulBitCount, sizeof( rgubLength ) );

	static const u8 k_rgubPadding[64] = { 0x80 };
	const u32 ibBuffer = static_cast<u32>( ( m_ulBitCount >> 3 ) & 0x3F );
	const u32 cubPadding = ( ibBuffer < 56 ) ? ( 56 - ibBuffer ) : ( 120 - ibBuffer );
	Update( k_rgubPadding, cubPadding );
	Update( rgubLength, 8 );

	for ( u32 iWord = 0; iWord < 4; ++iWord )
	{
		pubDigest[iWord * 4] = static_cast<u8>( m_rgunState[iWord] );
		pubDigest[iWord * 4 + 1] = static_cast<u8>( m_rgunState[iWord] >> 8 );
		pubDigest[iWord * 4 + 2] = static_cast<u8>( m_rgunState[iWord] >> 16 );
		pubDigest[iWord * 4 + 3] = static_cast<u8>( m_rgunState[iWord] >> 24 );
	}

	memset( this, 0, sizeof( *this ) );
}

} // namespace vac::crypto::hash
