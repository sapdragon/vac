#pragma once

#include "core/types.hpp"

namespace vac::util
{

[[nodiscard]] void *HeapAlloc( usize cubSize ) noexcept;
void HeapFree( void *pMemory ) noexcept;

} // namespace vac::util
