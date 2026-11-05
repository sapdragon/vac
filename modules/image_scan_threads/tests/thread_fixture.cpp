#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdlib>

static DWORD WINAPI parked( void * )
{
	Sleep( INFINITE );
	return 0;
}
int main( int argc, char **argv )
{
	unsigned count = argc > 1 ? static_cast<unsigned>( std::strtoul( argv[1], nullptr, 10 ) ) : 1;
	if ( count > 320 )
		return 2;
	for ( unsigned i = 0; i < count; ++i )
	{
		LPTHREAD_START_ROUTINE start = parked;
		// Suspended threads let us test start addresses without executing them.
		if ( i == 0 || i == 1 )
		{
			void *wanted = i == 1 ? reinterpret_cast<void *>( 0x90000000ull ) : nullptr;
			void *page = VirtualAlloc( wanted, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
			if ( !page )
				return 3;
			*static_cast<unsigned char *>( page ) = 0xC3;
			start = reinterpret_cast<LPTHREAD_START_ROUTINE>( page );
		}
		HANDLE thread = CreateThread( nullptr, 0, start, nullptr, CREATE_SUSPENDED, nullptr );
		if ( !thread )
			return 4;
		CloseHandle( thread );
	}
	std::puts( "ready" );
	std::fflush( stdout );
	Sleep( INFINITE );
	return 0;
}
