// @binary: 9b85c913
#include "crypto/random/park_miller.hpp"

namespace vac::crypto::random
{

namespace
{

constexpr i32 k_nMultiplier = 16807;
constexpr i32 k_nModulus = 0x7FFFFFFF;
constexpr i32 k_nQuotient = 127773;
constexpr i32 k_cWarmupRounds = 40;
constexpr i32 k_cShuffle = 32;

// @note / sapdragon: relies on signed wrap, both products overflow the same way
constexpr i32 Step( i32 nSeed ) noexcept
{
	const i32 nResult = static_cast<i32>( static_cast<u32>( k_nMultiplier ) * static_cast<u32>( nSeed ) -
	                                      static_cast<u32>( k_nModulus ) * static_cast<u32>( nSeed / k_nQuotient ) );
	return nResult < 0 ? nResult + k_nModulus : nResult;
}

} // namespace

// @orig: inlined
ParkMiller_t::ParkMiller_t( u32 unSeed ) noexcept : m_rgnShuffle{}
{
	// @note / sapdragon: the seed gets negated, so any positive seed collapses to 1. same in the original
	i32 nSeed = static_cast<i32>( 0u - unSeed );
	if ( nSeed < 1 )
		nSeed = 1;

	for ( i32 iRound = k_cWarmupRounds - 1; iRound >= 0; --iRound )
	{
		nSeed = Step( nSeed );
		if ( iRound < k_cShuffle )
			m_rgnShuffle[iRound] = nSeed;
	}
	m_nSeed = nSeed;
	m_nOutput = m_rgnShuffle[0];
}

// @orig: 51 53 56 57 8B F9
u32 ParkMiller_t::Next() noexcept
{
	const i32 nSeed = Step( m_nSeed );

	const u32 iBucket = static_cast<u32>( m_nOutput ) >> 26;
	m_nOutput = m_rgnShuffle[iBucket];
	m_rgnShuffle[iBucket] = nSeed;
	m_nSeed = nSeed;
	return static_cast<u32>( m_nOutput );
}

} // namespace vac::crypto::random
