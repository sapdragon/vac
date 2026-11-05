// A module for the service tests. Requests: 0 echoes through a relocated pointer, 1 faults, 2 asks for too much output,
// 3 returns a custom result.
#include <cstdint>

static int s_nRelocationProbe = 0x1234;
static int *volatile s_pnRelocationProbe = &s_nRelocationProbe;

extern "C" __declspec( dllexport ) int __stdcall runfunc( int nRequest, const void *pvInput, uint32_t cubInput,
                                                          void *pvOutput, uint32_t *pcubOutput )
{
	auto *punOutput = static_cast<uint32_t *>( pvOutput );
	switch ( nRequest )
	{
	case 0:
		punOutput[0] = static_cast<uint32_t>( *s_pnRelocationProbe );
		punOutput[1] = cubInput ? *static_cast<const uint8_t *>( pvInput ) : 0;
		*pcubOutput = 8;
		return 1;
	case 1:
		*static_cast<volatile int *>( nullptr ) = 1;
		return 1;
	case 2:
		*pcubOutput = 0x100000;
		return 1;
	default:
		return 77;
	}
}
