#pragma once

#include "core/packets.hpp"

namespace vac
{

enum class EDispatchResult : int
{
	Success = 1,
	NoDispatch = 3,
	BadArguments = 4,
};

[[nodiscard]] EDispatchResult __fastcall RunDispatcher( const VacInputPacket_t *pInput, u32 cubInput,
                                                        VacOutputPacket_t *pOutput, u32 *pcubOutput ) noexcept;

} // namespace vac
