// @binary: 42878040
#pragma once

#include "core/layout.hpp"
#include "core/types.hpp"

namespace vac::crypto::hash
{

inline constexpr u32 k_cubMd5Digest = 16;

struct Md5_t
{
	u32 m_rgunState[4];
	u64 m_ulBitCount;
	u8 m_rgubBuffer[64];

	Md5_t() noexcept { Init(); }

	// @orig: 83 61 ? ? 83 61
	void Init() noexcept
	{
		m_ulBitCount = 0;
		m_rgunState[0] = 0x67452301u;
		m_rgunState[1] = 0xEFCDAB89u;
		m_rgunState[2] = 0x98BADCFEu;
		m_rgunState[3] = 0x10325476u;
	}

	void Update( const u8 *pubData, usize cubData ) noexcept;

	// @note / sapdragon: wipes the whole context like the original. call Init before using it again
	void Final( u8 *pubDigest ) noexcept;

	static void Of( const u8 *pubData, usize cubData, u8 *pubDigest ) noexcept
	{
		Md5_t md5;
		md5.Update( pubData, cubData );
		md5.Final( pubDigest );
	}

	void Transform( const u8 *pubBlock ) noexcept;
};
VAC_LAYOUT( Md5_t, m_ulBitCount, 0x10 );
VAC_LAYOUT( Md5_t, m_rgubBuffer, 0x18 );
VAC_LAYOUT_SIZE( Md5_t, 0x58 );

} // namespace vac::crypto::hash
