#pragma once

#include "core/layout.hpp"
#include "core/types.hpp"

#include <type_traits>

namespace vac
{

using PfnWorker_t = int( __cdecl * )( const u8 *pubInput, u8 *pubOutput, u32 *pcubOutput );
using PfnInitializer_t = void( __cdecl * )();

struct Module_t
{
	Module_t *m_pNext;
	u32 m_unId;
	u32 m_unVersion;
	PfnWorker_t m_pfnWorker;
	u8 m_rgubIceKey[36];
};
VAC_LAYOUT( Module_t, m_unId, 0x04 );
VAC_LAYOUT( Module_t, m_pfnWorker, 0x0C );
VAC_LAYOUT( Module_t, m_rgubIceKey, 0x10 );
VAC_LAYOUT_SIZE( Module_t, 0x34 );

extern Module_t *g_pModuleListHead;

namespace detail
{

template <auto pfnWorker>
struct WorkerThunk_t;

template <typename Input_t, typename Output_t, int ( *pfnWorker )( Input_t &, Output_t &, u32 * ) noexcept>
struct WorkerThunk_t<pfnWorker>
{
	static int __cdecl Call( const u8 *pubInput, u8 *pubOutput, u32 *pcubOutput )
	{
		// @note / sapdragon: some workers write back into their input, so constness follows the worker's signature
		auto *pInput = reinterpret_cast<Input_t *>( const_cast<u8 *>( pubInput ) );
		return pfnWorker( *pInput, *reinterpret_cast<Output_t *>( pubOutput ), pcubOutput );
	}
};

template <int ( *pfnWorker )( const u8 *, u8 *, u32 * ) noexcept>
struct WorkerThunk_t<pfnWorker>
{
	static int __cdecl Call( const u8 *pubInput, u8 *pubOutput, u32 *pcubOutput )
	{
		return pfnWorker( pubInput, pubOutput, pcubOutput );
	}
};

} // namespace detail

} // namespace vac

#pragma section( ".vacini$a", read )
#pragma section( ".vacini$m", read )
#pragma section( ".vacini$z", read )

#define VAC_DETAIL_WORKER( pfnWorker, unId, unVersion, nUnique, ... )                                                  \
	static ::vac::Module_t s_WorkerNode##nUnique{                                                                      \
	    nullptr, ( unId ), ( unVersion ), &::vac::detail::WorkerThunk_t<&pfnWorker>::Call, { __VA_ARGS__ } };          \
	static void __cdecl RegisterWorkerNode##nUnique()                                                                  \
	{                                                                                                                  \
		s_WorkerNode##nUnique.m_pNext = ::vac::g_pModuleListHead;                                                      \
		::vac::g_pModuleListHead = &s_WorkerNode##nUnique;                                                             \
	}                                                                                                                  \
	extern "C" __declspec( allocate( ".vacini$m" ) ) const ::vac::PfnInitializer_t g_pfnRegisterWorkerNode##nUnique;   \
	__declspec( allocate( ".vacini$m" ) ) const ::vac::PfnInitializer_t g_pfnRegisterWorkerNode##nUnique =             \
	    RegisterWorkerNode##nUnique

#define VAC_DETAIL_WORKER_EXPAND( pfnWorker, unId, unVersion, nUnique, ... )                                           \
	VAC_DETAIL_WORKER( pfnWorker, unId, unVersion, nUnique, __VA_ARGS__ )

#define VAC_WORKER( pfnWorker, unId, unVersion, ... )                                                                  \
	VAC_DETAIL_WORKER_EXPAND( pfnWorker, unId, unVersion, __COUNTER__, __VA_ARGS__ )
