#pragma once

#include <Windows.h>

#include <evntcons.h>
#include <evntrace.h>

#include <cstdint>

namespace ETWWin32
{

// @note / sapdragon: the bits are valve's, the names are ours
enum EErrorFlags : uint32_t
{
	EF_TRACE_THREAD_STARTED = 0x1,
	EF_POLLING_THREAD_STARTED = 0x2,
	EF_POLLING_THREAD_FAILED = 0x4,
	EF_NO_IMAGE_PATH_API = 0x10,
	EF_NO_OS_VERSION = 0x20,
	EF_START_TRACE_FAILED = 0x100,
	EF_OPEN_TRACE_FAILED = 0x200,
	EF_ENABLE_TRACE_FAILED = 0x400,
};

bool BEnumProcessIds( uint32_t cubPids, DWORD *prgunPids, uint32_t *pcubPids );
bool BGetCreationTimeForPid( DWORD unPid, FILETIME *pCreationTime );
bool BGetImagePathForPid( DWORD unPid, wchar_t *pwszPath, uint32_t *pcchPath );
bool BIsETWStarted();
bool BStartETW();
void StopETW();
void GetCurrentTimeAsEventTime( FILETIME *pEventTime );
int NReadAvailableEvents( void *pvBuffer, uint32_t *pcubBuffer );
void WINAPI EventCallback( PEVENT_RECORD pEvent );

// @note / sapdragon: stand only. BStartETW stops any session with this name first, and the real steamservice runs one
// called "Steam Event Tracing" on any box with steam on it. anything that isn't the real service has to rename it first
void SetSessionName( const char *pszSessionName );
const char *GetSessionName();
void SetStartedForStand( bool bStarted );
uint32_t GetErrorFlags();

} // namespace ETWWin32
