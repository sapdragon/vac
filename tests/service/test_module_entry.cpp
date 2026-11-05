// A module with an entry point and no runfunc, for the loader paths the real modules never take.
#include <Windows.h>

static LONG s_cAttach = 0;
static LONG s_cDetach = 0;

extern "C" BOOL WINAPI EntryPoint( void *, DWORD unReason, void * )
{
	if ( unReason == DLL_PROCESS_ATTACH )
		++s_cAttach;
	else if ( unReason == DLL_PROCESS_DETACH )
		++s_cDetach;
	return TRUE;
}

extern "C" __declspec( dllexport ) BOOL WINAPI FailingEntry( void *, DWORD, void * )
{
	return FALSE;
}

extern "C" __declspec( dllexport ) LONG __stdcall AttachCount()
{
	return s_cAttach;
}

extern "C" __declspec( dllexport ) LONG *__stdcall DetachCounter()
{
	return &s_cDetach;
}

extern "C" __declspec( dllexport ) DWORD __stdcall ImportProbe()
{
	return GetCurrentProcessId();
}
