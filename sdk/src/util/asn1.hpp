// @binary: 9b85c913
#pragma once

#include "core/types.hpp"

namespace vac::util
{

enum class EAsn1Tag : u8
{
	Integer = 0x02,
	BitString = 0x03,
	OctetString = 0x04,
	Sequence = 0x30,
};

// @orig: 53 8B 5C 24 ? 55 8B 6C 24 ? 56 33 F6
constexpr bool ParseTlv( EAsn1Tag eExpectedTag, const u8 *pubData, u32 cubData, const u8 *&pubValue,
                         u32 &cubValue ) noexcept
{
	pubValue = nullptr;
	cubValue = 0;
	if ( cubData < 2 || pubData[0] != static_cast<u8>( eExpectedTag ) )
		return false;

	const u8 unLengthByte = pubData[1];
	u32 ibValue;
	u32 cubBody;

	if ( ( unLengthByte & 0x80 ) == 0 )
	{
		cubBody = unLengthByte & 0x7F;
		ibValue = 2;
	}
	else
	{
		const u32 cLengthBytes = unLengthByte & 0x7F;
		if ( cLengthBytes < 1 || cLengthBytes > 4 || cLengthBytes + 2u > cubData )
			return false;
		cubBody = 0;
		for ( u32 iByte = 0; iByte < cLengthBytes; ++iByte )
			cubBody = ( cubBody << 8 ) | u32( pubData[2 + iByte] );
		ibValue = 2 + cLengthBytes;
	}

	if ( ibValue + cubBody > cubData )
		return false;
	if ( cubBody + ibValue < cubBody )
		return false;

	pubValue = pubData + ibValue;
	cubValue = cubBody;
	return true;
}

} // namespace vac::util
