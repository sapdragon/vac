// @binary: 9b85c913
#include "crypto/bigint/bigint.hpp"
#include "core/vac_util.hpp"

// @note / sapdragon: a plain u64 product pulls the crt's _allmul on x86, this intrinsic stays a single mul
extern "C" unsigned __int64 __emulu( unsigned int unA, unsigned int unB );
#pragma intrinsic( __emulu )

namespace vac::crypto::bigint
{

void Bignum_t::Destroy() noexcept
{
	if ( m_punData )
		util::HeapFree( m_punData );
	m_punData = nullptr;
	m_cAllocated = 0;
	m_cUsed = 0;
	m_cBits = 0;
}

// @orig: 56 8B F1 57 8B 7C 24
void Bignum_t::EnsureAlloc( u32 cWords ) noexcept
{
	if ( m_cAllocated >= cWords )
		return;

	u32 *const punOld = m_punData;
	const usize cubNew = ( u64( cWords ) >> 30 ) ? usize( -1 ) : usize( cWords ) * 4;
	auto *const punNew = static_cast<u32 *>( util::HeapAlloc( cubNew ) );
	for ( u32 iWord = 0; iWord < m_cUsed; ++iWord )
		punNew[iWord] = punOld[iWord];

	m_punData = punNew;
	m_cAllocated = cWords;
	if ( punOld )
		util::HeapFree( punOld );
}

// @orig: 56 FF 74 24 ? 8B F1
void Bignum_t::ZeroExtend( u32 cWords ) noexcept
{
	EnsureAlloc( cWords );
	while ( m_cUsed < cWords )
		m_punData[m_cUsed++] = 0;
	m_cBits = 32 * m_cUsed;
}

// @orig: 8B 51 ? 56 33 F6
void Bignum_t::RecalcBits() noexcept
{
	while ( m_cUsed > 0 && m_punData[m_cUsed - 1] == 0 )
		--m_cUsed;
	if ( m_cUsed == 0 )
	{
		m_cBits = 0;
		return;
	}

	const u32 unTop = m_punData[m_cUsed - 1];
	u32 iHighestBit = 0;
	for ( u32 iBit = 31;; --iBit )
	{
		if ( unTop & ( 1u << iBit ) )
		{
			iHighestBit = iBit;
			break;
		}
		if ( iBit == 0 )
			break;
	}
	m_cBits = 32 * ( m_cUsed - 1 ) + iHighestBit + 1;
}

// @orig: 8B 54 24 ? 53 55 8B E9 8B 02
void Bignum_t::Swap( Bignum_t &other ) noexcept
{
	Bignum_t temp = *this;
	*this = other;
	other = temp;
}

// @orig: 56 6A ? 8B F1
void Bignum_t::SetInt( u32 unValue ) noexcept
{
	EnsureAlloc( 1 );
	m_punData[0] = unValue;
	m_cUsed = 1;
	m_cBits = 32;
	RecalcBits();
}

// @orig: 53 56 8B 74 24
void Bignum_t::SetBytes( const u8 *pubData, usize cubData ) noexcept
{
	m_cBits = 0;
	m_cUsed = 0;
	ZeroExtend( static_cast<u32>( ( cubData + 3 ) >> 2 ) );
	auto *const pubWords = reinterpret_cast<u8 *>( m_punData );
	for ( usize ib = 0; ib < cubData; ++ib )
		pubWords[ib] = pubData[cubData - 1 - ib];
	RecalcBits();
}

// @orig: 53 8B 5C 24 ? 56
void Bignum_t::CopyFrom( const Bignum_t &source ) noexcept
{
	m_punData = nullptr;
	m_cAllocated = 0;
	m_cUsed = 0;
	m_cBits = 0;
	EnsureAlloc( source.m_cUsed );
	m_cUsed = source.m_cUsed;
	m_cBits = source.m_cBits;
	for ( u32 iWord = 0; iWord < m_cUsed; ++iWord )
		m_punData[iWord] = source.m_punData[iWord];
}

// @orig: 51 53 55 56 8B 74 24
void Bignum_t::Add( const Bignum_t &other, u32 iWordOffset ) noexcept
{
	u32 cNeeded = iWordOffset + other.m_cUsed;
	if ( m_cUsed > cNeeded )
		cNeeded = m_cUsed;
	ZeroExtend( cNeeded + 1 );

	u64 ulCarry = 0;
	for ( u32 iWord = 0; iWord < other.m_cUsed; ++iWord )
	{
		const u64 ulSum = u64( m_punData[iWordOffset + iWord] ) + u64( other.m_punData[iWord] ) + ulCarry;
		m_punData[iWordOffset + iWord] = u32( ulSum );
		ulCarry = ulSum >> 32;
	}
	u32 iWord = iWordOffset + other.m_cUsed;
	while ( ulCarry )
	{
		const u64 ulSum = u64( m_punData[iWord] ) + ulCarry;
		m_punData[iWord] = u32( ulSum );
		ulCarry = ulSum >> 32;
		++iWord;
	}

	if ( m_cUsed > 0 && m_punData[m_cUsed - 1] == 0 )
	{
		m_cBits -= 32;
		--m_cUsed;
	}
}

// @orig: 83 EC ? 53 8B 5C 24
void Bignum_t::Multiply( const Bignum_t &other ) noexcept
{
	Bignum_t result;
	Bignum_t row;
	result.ZeroExtend( m_cUsed + other.m_cUsed + 2 );
	row.ZeroExtend( other.m_cUsed + 1 );

	for ( u32 iWord = 0; iWord < m_cUsed; ++iWord )
	{
		const u32 unMultiplier = m_punData[iWord];
		u64 ulCarry = 0;
		for ( u32 iOther = 0; iOther < other.m_cUsed; ++iOther )
		{
			const u64 ulProduct = __emulu( other.m_punData[iOther], unMultiplier ) + ulCarry;
			row.m_punData[iOther] = u32( ulProduct );
			ulCarry = ulProduct >> 32;
		}
		row.m_punData[other.m_cUsed] = u32( ulCarry );
		result.Add( row, iWord );
	}
	result.RecalcBits();
	Swap( result );

	row.Destroy();
	result.Destroy();
}

// @orig: 51 56 8B F1 89 74 24
void Bignum_t::ShiftRight( u32 cBits, u32 iStartWord ) noexcept
{
	if ( m_cBits == 0 || cBits == 0 )
		return;
	if ( cBits >= m_cBits )
	{
		m_cBits = 0;
		m_cUsed = 0;
		return;
	}

	const u32 cWordShift = cBits >> 5;
	const u32 cBitShift = cBits & 0x1F;

	if ( cWordShift )
	{
		u32 iSource = cWordShift + iStartWord;
		u32 iTarget = iStartWord;
		while ( iSource < m_cUsed )
			m_punData[iTarget++] = m_punData[iSource++];
		m_cUsed -= cWordShift;
		m_cBits -= 32 * cWordShift;
	}

	if ( cBitShift )
	{
		const u32 iLast = m_cUsed - 1;
		for ( u32 iWord = iStartWord; iWord < iLast; ++iWord )
			m_punData[iWord] = ( m_punData[iWord] >> cBitShift ) | ( m_punData[iWord + 1] << ( 32 - cBitShift ) );
		m_punData[iLast] >>= cBitShift;
		m_cBits -= cBitShift;
		m_cUsed = ( m_cBits + 31 ) >> 5;
	}
}

// @orig: 55 8B EC 83 EC ? 33 C0
void Bignum_t::PowerOfTwo( u32 unExponent ) noexcept
{
	Bignum_t shifted;
	Bignum_t one;
	one.SetInt( 1u << ( unExponent & 0x1F ) );
	shifted.Add( one, unExponent >> 5 );
	one.Destroy();
	Multiply( shifted );
	shifted.Destroy();
}

// @orig: 51 53 8B 5C 24
bool Bignum_t::CompareSub( const Bignum_t &other, u32 iShift ) noexcept
{
	if ( iShift >= other.m_cUsed )
		return false;
	if ( m_cBits < other.m_cBits )
		return false;

	if ( m_cBits == other.m_cBits )
	{
		for ( u32 iWord = other.m_cUsed; iWord > iShift; )
		{
			--iWord;
			if ( m_punData[iWord] < other.m_punData[iWord] )
				return false;
			if ( m_punData[iWord] > other.m_punData[iWord] )
				break;
		}
	}

	u64 ulBorrow = 0;
	u32 iWord = 0;
	for ( ; iWord < other.m_cUsed - iShift; ++iWord )
	{
		const u64 ulDifference = u64( m_punData[iShift + iWord] ) - u64( other.m_punData[iShift + iWord] ) - ulBorrow;
		m_punData[iShift + iWord] = u32( ulDifference );
		ulBorrow = ( ulDifference >> 32 ) & 1;
	}
	while ( ulBorrow )
	{
		const u64 ulDifference = u64( m_punData[iShift + iWord] ) - ulBorrow;
		m_punData[iShift + iWord] = u32( ulDifference );
		ulBorrow = ( ulDifference >> 32 ) & 1;
		++iWord;
	}

	RecalcBits();
	return true;
}

// @orig: 55 8B EC 83 EC ? 53 56 8B 75
void Bignum_t::DivMod( const Bignum_t &divisor, Bignum_t &remainder ) noexcept
{
	if ( divisor.m_cBits == 0 )
		return;

	Bignum_t shifted;
	shifted.CopyFrom( divisor );
	u32 cShift = ( divisor.m_cBits < m_cBits ) ? m_cBits - divisor.m_cBits : 0;
	shifted.PowerOfTwo( cShift );

	Swap( remainder );
	m_cBits = 0;
	m_cUsed = 0;
	u32 iWord = cShift >> 5;
	ZeroExtend( iWord + 1 );

	for ( ;; )
	{
		if ( remainder.CompareSub( shifted, iWord ) )
			m_punData[iWord] |= ( 1u << ( cShift & 0x1F ) );
		if ( cShift == 0 )
			break;
		--cShift;
		iWord = cShift >> 5;
		shifted.ShiftRight( 1, iWord );
	}

	RecalcBits();
	shifted.Destroy();
}

// @orig: 55 8B EC 83 EC ? 53 56 57 8B 7D
void Bignum_t::Modulo( const Bignum_t &modulus, const Bignum_t &barrett ) noexcept
{
	if ( m_cBits > modulus.m_cBits )
	{
		Bignum_t scratch;
		scratch.CopyFrom( *this );
		scratch.ShiftRight( 32 * modulus.m_cUsed - 32, 0 );
		scratch.Multiply( barrett );
		scratch.ShiftRight( 32 * ( modulus.m_cUsed + 1 ), 0 );
		scratch.Multiply( modulus );

		if ( scratch.m_cUsed > modulus.m_cUsed + 1 )
		{
			scratch.m_cUsed = modulus.m_cUsed + 1;
			scratch.m_cBits = 32 * ( modulus.m_cUsed + 1 );
			scratch.RecalcBits();
		}
		if ( m_cUsed > modulus.m_cUsed + 1 )
		{
			m_cUsed = modulus.m_cUsed + 1;
			m_cBits = 32 * ( modulus.m_cUsed + 1 );
			RecalcBits();
		}
		if ( !CompareSub( scratch, 0 ) )
		{
			ZeroExtend( modulus.m_cUsed + 2 );
			m_punData[modulus.m_cUsed + 1] = 1;
			RecalcBits();
			CompareSub( scratch, 0 );
		}
		scratch.Destroy();
	}
	while ( CompareSub( modulus, 0 ) )
	{
	}
}

// @orig: 83 EC ? 53 55 56 8B F1
void Bignum_t::ModExp( const Bignum_t &exponent, const Bignum_t &modulus ) noexcept
{
	if ( m_cBits == 0 || modulus.m_cBits == 0 )
		return;

	if ( &exponent == this || &modulus == this )
	{
		Bignum_t exponentCopy;
		Bignum_t modulusCopy;
		exponentCopy.CopyFrom( exponent );
		modulusCopy.CopyFrom( modulus );
		ModExp( exponentCopy, modulusCopy );
		exponentCopy.Destroy();
		modulusCopy.Destroy();
		return;
	}

	Bignum_t barrett;
	barrett.SetInt( 1 );
	barrett.PowerOfTwo( modulus.m_cUsed << 6 );

	Bignum_t remainder;
	barrett.DivMod( modulus, remainder );

	Bignum_t base;
	base.CopyFrom( *this );
	if ( m_cBits > 2 * modulus.m_cBits )
		DivMod( modulus, base );
	else
		base.Modulo( modulus, barrett );

	EnsureAlloc( 2 * modulus.m_cUsed + 3 );
	m_punData[0] = 1;
	m_cUsed = 1;
	m_cBits = 32;
	RecalcBits();

	u32 cBitsLeft = exponent.m_cBits;
	while ( cBitsLeft )
	{
		--cBitsLeft;
		Multiply( *this );
		Modulo( modulus, barrett );
		const bool bBitSet = ( exponent.m_punData[cBitsLeft >> 5] >> ( cBitsLeft & 0x1F ) ) & 1u;
		if ( bBitSet )
		{
			Multiply( base );
			Modulo( modulus, barrett );
		}
	}

	base.Destroy();
	remainder.Destroy();
	barrett.Destroy();
}

} // namespace vac::crypto::bigint
