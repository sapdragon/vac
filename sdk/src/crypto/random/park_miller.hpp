#pragma once

#include "core/types.hpp"

namespace vac::crypto::random
{

struct ParkMiller_t
{
	i32 m_nSeed;
	i32 m_nOutput;
	i32 m_rgnShuffle[32];

	explicit ParkMiller_t( u32 unSeed ) noexcept;

	u32 Next() noexcept;
};

} // namespace vac::crypto::random
