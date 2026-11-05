// @binary: 9b85c913
#include "crypto/rsa/rsa.hpp"
#include "util/asn1.hpp"

namespace vac::crypto::rsa
{

namespace
{

constexpr u8 k_rgubRsaEncryptionId[] = {
    0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
};

constexpr bool BytesEqual( const u8 *pubA, const u8 *pubB, usize cub ) noexcept
{
	for ( usize ib = 0; ib < cub; ++ib )
	{
		if ( pubA[ib] != pubB[ib] )
			return false;
	}
	return true;
}

} // namespace

// @orig: 51 51 53 55 56
bool ParsePublicKey( const u8 *pubKey, u32 cubKey, bigint::Bignum_t &exponent, bigint::Bignum_t &modulus ) noexcept
{
	const u8 *pubOuter;
	u32 cubOuter;
	if ( !util::ParseTlv( util::EAsn1Tag::Sequence, pubKey, cubKey, pubOuter, cubOuter ) )
		return false;
	if ( cubOuter <= sizeof( k_rgubRsaEncryptionId ) )
		return false;

	if ( !BytesEqual( pubOuter, k_rgubRsaEncryptionId, sizeof( k_rgubRsaEncryptionId ) ) )
		return false;
	const u8 *pubAfterId = pubOuter + sizeof( k_rgubRsaEncryptionId );
	const u32 cubAfterId = cubOuter - sizeof( k_rgubRsaEncryptionId );

	const u8 *pubBitString;
	u32 cubBitString;
	if ( !util::ParseTlv( util::EAsn1Tag::BitString, pubAfterId, cubAfterId, pubBitString, cubBitString ) )
		return false;
	if ( cubBitString == 0 )
		return false;

	const u8 *pubSpki = pubBitString + 1;
	const u32 cubSpki = cubBitString - 1;

	const u8 *pubInner;
	u32 cubInner;
	if ( !util::ParseTlv( util::EAsn1Tag::Sequence, pubSpki, cubSpki, pubInner, cubInner ) )
		return false;

	const u8 *pubModulus;
	u32 cubModulus;
	if ( !util::ParseTlv( util::EAsn1Tag::Integer, pubInner, cubInner, pubModulus, cubModulus ) )
		return false;

	const u32 ibExponent = u32( ( pubModulus - pubInner ) + cubModulus );
	if ( ibExponent > cubInner )
		return false;
	const u8 *pubExponent;
	u32 cubExponent;
	if ( !util::ParseTlv( util::EAsn1Tag::Integer, pubInner + ibExponent, cubInner - ibExponent, pubExponent,
	                      cubExponent ) )
		return false;

	if ( cubModulus > 0 && pubModulus[0] == 0 )
	{
		++pubModulus;
		--cubModulus;
	}
	if ( cubExponent > 0 && pubExponent[0] == 0 )
	{
		++pubExponent;
		--cubExponent;
	}

	modulus.SetBytes( pubModulus, cubModulus );
	exponent.SetBytes( pubExponent, cubExponent );
	return true;
}

// @orig: 81 EC ? ? ? ? 8B 94 24
bool EncryptSessionKey( const u8 *pubSessionKey, u32 cubSessionKey, const u8 *pubKey, u32 cubKey, u8 *pubOutput,
                        u32 *pcubOutput, ERsaError *peError ) noexcept
{
	*peError = ERsaError::Ok;

	bigint::Bignum_t exponent;
	bigint::Bignum_t modulus;
	if ( !ParsePublicKey( pubKey, cubKey, exponent, modulus ) )
	{
		*peError = ERsaError::ParseFailed;
		exponent.Destroy();
		modulus.Destroy();
		return false;
	}

	if ( modulus.m_cBits > 8192 )
	{
		*peError = ERsaError::BadKeySize;
		exponent.Destroy();
		modulus.Destroy();
		return false;
	}

	bigint::Bignum_t message;
	message.SetBytes( pubSessionKey, cubSessionKey );

	message.ModExp( exponent, modulus );

	const u32 cubResult = ( message.m_cBits + 7 ) >> 3;
	if ( cubResult > 1024 )
	{
		*peError = ERsaError::BadKeySize;
		message.Destroy();
		exponent.Destroy();
		modulus.Destroy();
		return false;
	}

	if ( cubResult > *pcubOutput )
	{
		*peError = ERsaError::BufferTooSmall;
		*pcubOutput = cubResult;
		message.Destroy();
		exponent.Destroy();
		modulus.Destroy();
		return false;
	}

	const u32 cubPadding = *pcubOutput - cubResult;
	for ( u32 ib = 0; ib < cubPadding; ++ib )
		pubOutput[ib] = 0;
	const auto *pubMessage = reinterpret_cast<const u8 *>( message.m_punData );
	for ( u32 ib = 0; ib < cubResult; ++ib )
		pubOutput[cubPadding + ib] = pubMessage[cubResult - 1 - ib];

	message.Destroy();
	exponent.Destroy();
	modulus.Destroy();
	return true;
}

} // namespace vac::crypto::rsa
