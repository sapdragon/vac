#pragma once

#include "core/types.hpp"

namespace vac::crypto::bigint
{

struct Bignum_t
{
	u32 *m_punData = nullptr;
	u32 m_cAllocated = 0;
	u32 m_cUsed = 0;
	u32 m_cBits = 0;

	void Destroy() noexcept;

	void SetInt( u32 unValue ) noexcept;

	void SetBytes( const u8 *pubData, usize cubData ) noexcept;

	void CopyFrom( const Bignum_t &source ) noexcept;

	void Add( const Bignum_t &other, u32 iWordOffset ) noexcept;
	void Multiply( const Bignum_t &other ) noexcept;
	void ShiftRight( u32 cBits, u32 iStartWord ) noexcept;
	void PowerOfTwo( u32 unExponent ) noexcept;
	void DivMod( const Bignum_t &divisor, Bignum_t &remainder ) noexcept;

	bool CompareSub( const Bignum_t &other, u32 iShift ) noexcept;
	void Modulo( const Bignum_t &modulus, const Bignum_t &barrett ) noexcept;
	void ModExp( const Bignum_t &exponent, const Bignum_t &modulus ) noexcept;

	void Swap( Bignum_t &other ) noexcept;
	void EnsureAlloc( u32 cWords ) noexcept;
	void RecalcBits() noexcept;
	void ZeroExtend( u32 cWords ) noexcept;
};

} // namespace vac::crypto::bigint
