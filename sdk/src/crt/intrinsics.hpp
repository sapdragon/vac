#pragma once

#include <cstddef>

// @note / sapdragon: no noexcept, <cstring> declares these without it and msvc rejects the mismatch

extern "C"
{
	void *memset( void *pDst, int nValue, std::size_t cub );
	void *memcpy( void *pDst, const void *pSrc, std::size_t cub );
	void *memmove( void *pDst, const void *pSrc, std::size_t cub );
	int memcmp( const void *pA, const void *pB, std::size_t cub );

	extern int _fltused;

#if defined( _M_IX86 )
	void _chkstk();
	void __chkstk();
	void _alloca_probe();
	void _alloca_probe_8();
	void _alloca_probe_16();
	void __alloca_probe();
	void __alloca_probe_8();
	void __alloca_probe_16();
#endif
}
