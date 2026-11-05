// @binary: 60e41c53
#include "types.hpp"
#include "crypto/bigint/bigint.hpp"
#include "util/asn1.hpp"
#include "crt/intrinsics.hpp"

namespace vac::workers::payload_executor
{
const u8 k_rgubBase[0x4000] = {
#include "base.inc"
};
namespace
{
// @orig: 83 EC ? 53 55 56 57 8D 44 24
bool ParsePrivateKey( const u8 *pubKey, u32 cubKey, const u8 *&pubModulus, u32 &cubModulus, const u8 *&pubExponent,
                      u32 &cubExponent ) noexcept
{
	using util::EAsn1Tag;
	using util::ParseTlv;
	static constexpr u8 k_rgubPrivateKeyPrefix[] = { 2,    1,    0,    0x30, 0x0D, 6, 9, 0x2A, 0x86,
	                                                 0x48, 0x86, 0xF7, 0x0D, 1,    1, 1, 5,    0 };
	const u8 *pubValue = nullptr;
	u32 cubValue = 0;
	if ( !ParseTlv( EAsn1Tag::Sequence, pubKey, cubKey, pubValue, cubValue ) ||
	     cubValue <= sizeof( k_rgubPrivateKeyPrefix ) ||
	     memcmp( pubValue, k_rgubPrivateKeyPrefix, sizeof( k_rgubPrivateKeyPrefix ) ) )
		return false;
	if ( !ParseTlv( EAsn1Tag::OctetString, pubValue + sizeof( k_rgubPrivateKeyPrefix ),
	                cubValue - sizeof( k_rgubPrivateKeyPrefix ), pubKey, cubKey ) ||
	     !cubKey )
		return false;
	if ( !ParseTlv( EAsn1Tag::Sequence, pubKey, cubKey, pubValue, cubValue ) )
		return false;
	const u8 *pubCursor = pubValue;
	u32 cubRemaining = cubValue;
	auto ParseInteger = [&]( const u8 *&pubInteger, u32 &cubInteger )
	{
		if ( !ParseTlv( EAsn1Tag::Integer, pubCursor, cubRemaining, pubInteger, cubInteger ) )
			return false;
		const u32 cubConsumed = static_cast<u32>( pubInteger - pubCursor ) + cubInteger;
		pubCursor += cubConsumed;
		cubRemaining -= cubConsumed;
		return true;
	};
	const u8 *pubIgnored = nullptr;
	u32 cubIgnored = 0;
	return ParseInteger( pubIgnored, cubIgnored ) && ParseInteger( pubModulus, cubModulus ) &&
	       ParseInteger( pubIgnored, cubIgnored ) && ParseInteger( pubExponent, cubExponent );
}
} // namespace

// @orig: 55 8B EC 83 E4 ? 81 EC ? ? ? ? 8B 55
bool DecryptPayload( const u8 *pubPacked, u32 cubPacked, u8 *pubOutput, u32 *pcubOutput, u32 *punError ) noexcept
{
	*punError = 0;
	const u8 *pubModulus = nullptr;
	const u8 *pubExponent = nullptr;
	u32 cubModulus = 0, cubExponent = 0;
	if ( !ParsePrivateKey( pubPacked, cubPacked, pubModulus, cubModulus, pubExponent, cubExponent ) )
	{
		*punError = 1;
		return false;
	}
	crypto::bigint::Bignum_t base, exponent, modulus;
	base.SetBytes( k_rgubBase, sizeof( k_rgubBase ) );
	exponent.SetBytes( pubExponent, cubExponent );
	modulus.SetBytes( pubModulus, cubModulus );
	bool bSuccess = false;
	if ( ( ( modulus.m_cBits + 7u ) & ~7u ) <= 8192 )
	{
		base.ModExp( exponent, modulus );
		const u32 cubResult = ( base.m_cBits + 7 ) >> 3;
		if ( cubResult > 1024 )
			*punError = 2;
		else if ( cubResult > *pcubOutput )
		{
			*punError = 3;
			*pcubOutput = cubResult;
		}
		else
		{
			const u32 cubPadding = *pcubOutput - cubResult;
			memset( pubOutput, 0, cubPadding );
			const auto *pubResult = reinterpret_cast<const u8 *>( base.m_punData );
			for ( u32 ib = 0; ib < cubResult; ++ib )
				pubOutput[cubPadding + ib] = pubResult[cubResult - 1 - ib];
			bSuccess = true;
		}
	}
	else
		*punError = 2;
	modulus.Destroy();
	exponent.Destroy();
	base.Destroy();
	return bSuccess;
}
} // namespace vac::workers::payload_executor
