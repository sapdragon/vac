#pragma once

#include "core/types.hpp"
#include "crypto/bigint/bigint.hpp"

// @note / sapdragon: textbook rsa, no padding. that's what valve does

namespace vac::crypto::rsa
{

enum class ERsaError : u32
{
	Ok = 0,
	ParseFailed = 1,
	BadKeySize = 2,
	BufferTooSmall = 3,
};

[[nodiscard]] bool ParsePublicKey( const u8 *pubKey, u32 cubKey, bigint::Bignum_t &exponent,
                                   bigint::Bignum_t &modulus ) noexcept;

[[nodiscard]] bool EncryptSessionKey( const u8 *pubSessionKey, u32 cubSessionKey, const u8 *pubKey, u32 cubKey,
                                      u8 *pubOutput, u32 *pcubOutput, ERsaError *peError ) noexcept;

} // namespace vac::crypto::rsa
