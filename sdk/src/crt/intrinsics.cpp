// @binary: 42878040
#include "crt/intrinsics.hpp"

// @note / sapdragon: stops the compiler from turning these bodies into calls to themselves
#pragma function( memset, memcpy, memmove, memcmp )

extern "C"
{
	// @orig: 8B 4C 24 ? 85 C9
	void *memset( void *pDst, int nValue, std::size_t cub )
	{
		auto *pubDst = static_cast<unsigned char *>( pDst );
		const auto unValue = static_cast<unsigned char>( nValue );
		while ( cub-- )
			*pubDst++ = unValue;
		return pDst;
	}

	// @orig: 8B 54 24 ? 8B 44 24
	void *memcpy( void *pDst, const void *pSrc, std::size_t cub )
	{
		auto *pubDst = static_cast<unsigned char *>( pDst );
		const auto *pubSrc = static_cast<const unsigned char *>( pSrc );
		while ( cub-- )
			*pubDst++ = *pubSrc++;
		return pDst;
	}

	void *memmove( void *pDst, const void *pSrc, std::size_t cub )
	{
		auto *pubDst = static_cast<unsigned char *>( pDst );
		const auto *pubSrc = static_cast<const unsigned char *>( pSrc );
		if ( pubDst == pubSrc || cub == 0 )
			return pDst;
		if ( pubDst < pubSrc )
		{
			while ( cub-- )
				*pubDst++ = *pubSrc++;
		}
		else
		{
			pubDst += cub;
			pubSrc += cub;
			while ( cub-- )
				*--pubDst = *--pubSrc;
		}
		return pDst;
	}

	// @orig: 8B 44 24 ? 53
	int memcmp( const void *pA, const void *pB, std::size_t cub )
	{
		const auto *pubA = static_cast<const unsigned char *>( pA );
		const auto *pubB = static_cast<const unsigned char *>( pB );
		while ( cub-- )
		{
			// @note / sapdragon: returns the byte difference, not -1 or 1. same in the original
			if ( *pubA != *pubB )
				return *pubA - *pubB;
			++pubA;
			++pubB;
		}
		return 0;
	}

	int _fltused = 0;

#if defined( _M_IX86 )

	// clang-format off
	// @orig: 51 8D 4C 24 ? 2B C8
	__declspec( naked ) void _chkstk()
	{
		__asm
		{
			push ecx
			push edx

			// @note / sapdragon: esp after the ret has to be esp before the call minus eax
			lea  edx, [esp + 8]
			mov  ecx, edx
			sub  ecx, eax

		probe_pages:
			sub  edx, 1000h
			cmp  edx, ecx
			jb   probe_tail
			test dword ptr [edx], eax
			jmp  probe_pages

		probe_tail:
			test dword ptr [ecx], eax

			mov  eax, ecx
			mov  ecx, [esp + 8]
			mov  [eax], ecx
			mov  edx, [esp + 0]
			mov  ecx, [esp + 4]
			mov  esp, eax
			ret
		}
	}

	__declspec( naked ) void __chkstk() { __asm { jmp _chkstk } }
	__declspec( naked ) void _alloca_probe() { __asm { jmp _chkstk } }
	__declspec( naked ) void _alloca_probe_16() { __asm { jmp _chkstk } }
	__declspec( naked ) void _alloca_probe_8() { __asm { jmp _chkstk } }
	__declspec( naked ) void __alloca_probe() { __asm { jmp _chkstk } }
	__declspec( naked ) void __alloca_probe_16() { __asm { jmp _chkstk } }
	__declspec( naked ) void __alloca_probe_8() { __asm { jmp _chkstk } }
	// clang-format on

#endif
}
