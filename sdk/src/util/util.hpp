// @binary: 9b85c913
#pragma once

#include "bootstrap/imports.hpp"
#include "core/types.hpp"

namespace vac::util
{

enum class EProtectMode : u32
{
	NoAccess = 0b000,
	ReadOnly = 0b001,
	ReadWrite = 0b011,
	Execute = 0b100,
	ExecuteRead = 0b101,
	ExecuteReadWrite = 0b111,
};

// @orig: 83 C8 ? 83 E9
constexpr u32 MapProtectionFlags( EProtectMode eMode ) noexcept
{
	switch ( eMode )
	{
	case EProtectMode::NoAccess:
		return PAGE_NOACCESS;
	case EProtectMode::ReadOnly:
		return PAGE_READONLY;
	case EProtectMode::ReadWrite:
		return PAGE_READWRITE;
	case EProtectMode::Execute:
		return PAGE_EXECUTE;
	case EProtectMode::ExecuteRead:
		return PAGE_EXECUTE_READ;
	case EProtectMode::ExecuteReadWrite:
		return PAGE_EXECUTE_READWRITE;
	default:
		return ~u32( 0 );
	}
}

} // namespace vac::util
