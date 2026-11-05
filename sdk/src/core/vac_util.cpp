// @binary: 9b85c913
#include "core/vac_util.hpp"

#include <Windows.h>

namespace vac::util
{

// @orig: 9b85c913:0x10004F2B (no unique signature)
void *HeapAlloc( usize cubSize ) noexcept
{
	return ::HeapAlloc( GetProcessHeap(), 0, cubSize );
}

// @orig: 9b85c913:0x10004F3C (no unique signature)
void HeapFree( void *pMemory ) noexcept
{
	if ( pMemory )
		::HeapFree( GetProcessHeap(), 0, pMemory );
}

} // namespace vac::util
