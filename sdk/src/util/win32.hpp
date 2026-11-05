#pragma once

#include "bootstrap/imports.hpp"
#include "core/types.hpp"

namespace vac::util
{

// @orig: inlined everywhere
inline u32 GetLastError( const SystemImports_t *pImports ) noexcept
{
	return pImports && pImports->GetLastError ? pImports->GetLastError() : 0;
}

} // namespace vac::util
