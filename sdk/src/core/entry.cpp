// @binary: 9b85c913
#include "core/dispatcher.hpp"
#include "core/module.hpp"

#include <Windows.h>

#pragma comment( linker, "/merge:.vacini=.rdata" )

namespace vac
{

namespace
{

struct StdHandle_t
{
	u32 m_bInitialized;
	HANDLE m_hHandle;
};

constinit u32 s_cubHeapGranularity = 0;
constinit void *s_pubHeapScratch = nullptr;
constinit StdHandle_t s_rgStdHandles[3]{};

// @note / sapdragon: non-zero from the start, so the initializers always run again after dispatch
constinit u32 s_bRunInitializersAgain = 0xFFFFFFFFu;

// @orig: 6A ? B8
void __cdecl ClearStdHandleFlags()
{
	for ( StdHandle_t &stdHandle : s_rgStdHandles )
		stdHandle.m_bInitialized = 0;
}

__declspec( allocate( ".vacini$a" ) ) extern const PfnInitializer_t k_pfnInitializersBegin = nullptr;
__declspec( allocate( ".vacini$m" ) ) extern const PfnInitializer_t k_pfnClearStdHandleFlags = ClearStdHandleFlags;
__declspec( allocate( ".vacini$z" ) ) extern const PfnInitializer_t k_pfnInitializersEnd = nullptr;

// @orig: 51 53 56 57 BF
void CallInitializers() noexcept
{
	for ( const PfnInitializer_t *ppfnInit = &k_pfnInitializersBegin; ppfnInit < &k_pfnInitializersEnd; ++ppfnInit )
	{
		if ( *ppfnInit )
			( *ppfnInit )();
	}
}

} // namespace

} // namespace vac

// @orig: 55 8B EC 56 57
extern "C"
    __declspec( dllexport ) int __stdcall runfunc( int nMode, const vac::VacInputPacket_t *pInput, vac::u32 cubInput,
                                                   vac::VacOutputPacket_t *pOutput, vac::u32 *pcubOutput ) noexcept
{
	using namespace vac;

	s_cubHeapGranularity = 128;
	s_pubHeapScratch = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 0x200 );

	s_rgStdHandles[0].m_hHandle = GetStdHandle( STD_INPUT_HANDLE );
	s_rgStdHandles[0].m_bInitialized = 1;
	s_rgStdHandles[1].m_hHandle = GetStdHandle( STD_OUTPUT_HANDLE );
	s_rgStdHandles[1].m_bInitialized = 1;
	s_rgStdHandles[2].m_hHandle = GetStdHandle( STD_ERROR_HANDLE );
	s_rgStdHandles[2].m_bInitialized = 1;

	CallInitializers();

	EDispatchResult eResult = EDispatchResult::NoDispatch;
	if ( nMode == 4 )
		eResult = RunDispatcher( pInput, cubInput, pOutput, pcubOutput );

	if ( s_bRunInitializersAgain )
		CallInitializers();

	return static_cast<int>( eResult );
}
