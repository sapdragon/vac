// @binary: 7ebac2a4
#include "process_monitor/etwwin32.hpp"
#include "process_monitor/vacprocessmonitor.hpp"

#include <Psapi.h>

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <vector>

using VacProcessMonitor::EEventType;
using VacProcessMonitor::EventHeader_t;
using VacProcessMonitor::ProcessExitEvent_t;
using VacProcessMonitor::ProcessStartEvent_t;

namespace
{

using PfnQueryFullProcessImageNameW_t = BOOL( WINAPI * )( HANDLE, DWORD, LPWSTR, PDWORD );
using PfnGetProcessImageFileNameW_t = DWORD( WINAPI * )( HANDLE, LPWSTR, DWORD );

constexpr GUID k_KernelProcessGuid = { 0x22FB2CD6, 0x0E7B, 0x422B, { 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 } };

#pragma pack( push, 4 )

struct TraceProperties_t
{
	EVENT_TRACE_PROPERTIES m_Properties;
	char m_szLoggerName[20];
};
static_assert( sizeof( TraceProperties_t ) == 140 );

struct KernelProcessStartV0_t
{
	DWORD m_unPid;
	uint64_t m_ulCreationTime;
	DWORD m_unParentPid;
	DWORD m_unSessionId;
	wchar_t m_wszImageName[1];
};
static_assert( offsetof( KernelProcessStartV0_t, m_wszImageName ) == 20 );

struct KernelProcessStartV2_t
{
	DWORD m_unPid;
	uint64_t m_ulCreationTime;
	DWORD m_unParentPid;
	DWORD m_unSessionId;
	DWORD m_unFlags;
	wchar_t m_wszImageName[1];
};
static_assert( offsetof( KernelProcessStartV2_t, m_wszImageName ) == 24 );

struct KernelProcessStop_t
{
	DWORD m_unPid;
	uint64_t m_ulCreationTime;
	uint64_t m_ulExitTime;
	DWORD m_unExitCode;
};
static_assert( offsetof( KernelProcessStop_t, m_unExitCode ) == 20 );

#pragma pack( pop )

struct ProcessSnapshot_t
{
	DWORD m_rgunPids[1024];
	uint32_t m_cPids;
};
static_assert( sizeof( ProcessSnapshot_t ) == 4100 );

class CEventBuffer
{
public:
	CEventBuffer() : m_vecData( 0x100000 ), m_cubSize( 0x100000 ) {}

	int GetUsed() const { return m_cubUsed; }
	int GetSize() const { return m_cubSize; }
	int GetFree() const { return m_cubSize - m_cubUsed; }
	int Peek( void *pvOutput, int cubOutput ) const;
	int Read( void *pvOutput, int cubOutput );
	int Advance( int cubAdvance );
	int Write( const void *pvInput, int cubInput );

private:
	std::vector<uint8_t> m_vecData;
	int m_cubUsed = 0;
	int m_iRead = 0;
	int m_iWrite = 0;
	int m_cubSize;
};

// @orig: 55 8B EC 53 8B D9 8B 03
int CEventBuffer::Peek( void *pvOutput, int cubOutput ) const
{
	if ( !m_cubUsed )
		return 0;

	const int cubPeek = m_cubUsed < cubOutput ? m_cubUsed : cubOutput;
	if ( cubPeek + m_iRead <= m_cubSize )
	{
		memcpy( pvOutput, &m_vecData[m_iRead], cubPeek );
	}
	else
	{
		const int cubTail = m_cubSize - m_iRead;
		memcpy( pvOutput, &m_vecData[m_iRead], cubTail );
		memcpy( static_cast<uint8_t *>( pvOutput ) + cubTail, m_vecData.data(), cubPeek - cubTail );
	}
	return cubPeek;
}

// @orig: 7ebac2a4:0x10074340 (not in export)
int CEventBuffer::Advance( int cubAdvance )
{
	if ( !m_cubUsed )
		return 0;

	const int cubSkip = m_cubUsed < cubAdvance ? m_cubUsed : cubAdvance;
	m_iRead = ( cubSkip + m_iRead ) % m_cubSize;
	m_cubUsed -= cubSkip;
	if ( !m_cubUsed )
	{
		m_iRead = 0;
		m_iWrite = 0;
	}
	return cubSkip;
}

// @orig: 55 8B EC 53 56 57 8B F9 8B 07
int CEventBuffer::Read( void *pvOutput, int cubOutput )
{
	const int cubPeek = Peek( pvOutput, cubOutput );
	return cubPeek ? Advance( cubPeek ) : 0;
}

// @orig: 7ebac2a4:0x10074500 (not in export)
int CEventBuffer::Write( const void *pvInput, int cubInput )
{
	if ( cubInput <= 0 )
		return cubInput;

	auto *pubInput = static_cast<const uint8_t *>( pvInput );
	int cubLeft = cubInput;
	do
	{
		const int cubTail = m_cubSize - m_iWrite;
		const int cubChunk = cubTail <= cubLeft ? cubTail : cubLeft;
		memcpy( &m_vecData[m_iWrite], pubInput, cubChunk );
		m_iWrite = ( cubChunk + m_iWrite ) % m_cubSize;
		if ( cubChunk <= m_cubSize - m_cubUsed )
		{
			m_cubUsed += cubChunk;
		}
		else
		{
			m_iRead = m_iWrite;
			m_cubUsed = m_cubSize;
		}
		pubInput += cubChunk;
		cubLeft -= cubChunk;
	} while ( cubLeft > 0 );
	return cubInput;
}

class CEventQueue
{
public:
	CEventQueue() { InitializeCriticalSection( &m_CritSec ); }

	void Enqueue( const EventHeader_t *pEvent );

	CRITICAL_SECTION m_CritSec;
	CEventBuffer m_Buffer;
};

// @orig: 7ebac2a4:0x10048AA0 (not in export)
void CEventQueue::Enqueue( const EventHeader_t *pEvent )
{
	EnterCriticalSection( &m_CritSec );
	if ( static_cast<int>( pEvent->m_cubEvent ) <= m_Buffer.GetSize() )
	{
		while ( m_Buffer.GetFree() < static_cast<int>( pEvent->m_cubEvent ) )
		{
			EventHeader_t oldest;
			m_Buffer.Peek( &oldest, sizeof( oldest ) );
			m_Buffer.Advance( oldest.m_cubEvent );
		}
		m_Buffer.Write( pEvent, pEvent->m_cubEvent );
	}
	LeaveCriticalSection( &m_CritSec );
}

CEventQueue s_EventQueue;

bool s_bETWStarted = false;
bool s_bETWInitialised = false;
uint32_t s_unErrorFlags = 0;
TRACEHANDLE s_hTrace = 0;
HANDLE s_hThread = nullptr;
HANDLE s_hStopEvent = nullptr;
PfnQueryFullProcessImageNameW_t s_pfnQueryFullProcessImageNameW = nullptr;
PfnGetProcessImageFileNameW_t s_pfnGetProcessImageFileNameW = nullptr;
uint32_t s_unLastSequence = 0;
const char *s_pszSessionName = "Steam Event Tracing";

uint32_t NextSequence()
{
	uint32_t unSequence = s_unLastSequence;
	do
		++unSequence;
	while ( unSequence == 0xFFFFFFFF );
	s_unLastSequence = unSequence;
	return unSequence;
}

void ResolveImagePathFunctions()
{
	const HMODULE hPsapi = GetModuleHandleA( "psapi.dll" );
	if ( hPsapi )
		s_pfnGetProcessImageFileNameW =
		    reinterpret_cast<PfnGetProcessImageFileNameW_t>( GetProcAddress( hPsapi, "GetProcessImageFileNameW" ) );

	const HMODULE hKernel32 = GetModuleHandleA( "kernel32.dll" );
	if ( hKernel32 )
		s_pfnQueryFullProcessImageNameW = reinterpret_cast<PfnQueryFullProcessImageNameW_t>(
		    GetProcAddress( hKernel32, "QueryFullProcessImageNameW" ) );
}

void InitTraceProperties( TraceProperties_t *pProperties )
{
	memset( pProperties, 0, sizeof( *pProperties ) );
	pProperties->m_Properties.Wnode.BufferSize = sizeof( *pProperties );
	pProperties->m_Properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	pProperties->m_Properties.LoggerNameOffset = offsetof( TraceProperties_t, m_szLoggerName );
}

// @orig: 7ebac2a4:0x10048B50 (not in export)
int __cdecl ComparePids( const void *pvLeft, const void *pvRight )
{
	return *static_cast<const int *>( pvLeft ) - *static_cast<const int *>( pvRight );
}

// @orig: 7ebac2a4:0x100485D0 (not in export)
void WriteProcessStartEvent( uint64_t ulTimestamp, const wchar_t *pwszImagePath, DWORD unPid, DWORD unParentPid,
                             DWORD unSessionId, const void *pvCreationTime )
{
	ProcessStartEvent_t event;
	const size_t cchPath = wcslen( pwszImagePath );
	const int cchCopy = cchPath < 1024 ? static_cast<int>( cchPath ) : 1024;
	event.m_Header.m_cubEvent = 2 * cchCopy + 46;
	event.m_Header.m_unSequence = NextSequence();
	event.m_Header.m_ulTimestamp = ulTimestamp;
	event.m_unPid = unPid;
	event.m_unParentPid = unParentPid;
	event.m_unSessionId = unSessionId;
	event.m_Header.m_unVersion = 1;
	event.m_Header.m_eType = EEventType::ProcessStart;
	memcpy( &event.m_ulCreationTime, pvCreationTime, sizeof( event.m_ulCreationTime ) );
	memcpy( event.m_wszImagePath, pwszImagePath, 2 * cchCopy );
	event.m_wszImagePath[cchCopy] = L'\0';
	s_EventQueue.Enqueue( &event.m_Header );
}

// @orig: 7ebac2a4:0x100486B0 (not in export)
void WriteProcessExitEvent( uint64_t ulTimestamp, const KernelProcessStop_t *pStop )
{
	ProcessExitEvent_t event;
	event.m_Header.m_cubEvent = sizeof( ProcessExitEvent_t );
	event.m_Header.m_unSequence = NextSequence();
	event.m_Header.m_ulTimestamp = ulTimestamp;
	event.m_unPid = pStop->m_unPid;
	event.m_unExitCode = pStop->m_unExitCode;
	event.m_ulCreationTime = pStop->m_ulCreationTime;
	event.m_ulExitTime = pStop->m_ulExitTime;
	event.m_Header.m_unVersion = 1;
	event.m_Header.m_eType = EEventType::ProcessExit;
	s_EventQueue.Enqueue( &event.m_Header );
}

// @note / sapdragon: the path when etw won't start. it diffs EnumProcesses once a second, so parent and session are 0
// and creation time is just now. child processes can't be followed from these
// @orig: 7ebac2a4:0x10048730 (not in export)
void PollProcessList()
{
	ProcessSnapshot_t rgSnapshots[2];
	memset( rgSnapshots, 0, sizeof( rgSnapshots ) );

	int iSnapshot = 0;
	while ( s_bETWStarted )
	{
		ProcessSnapshot_t &current = rgSnapshots[iSnapshot];
		iSnapshot = ( iSnapshot + 1 ) % 2;
		const ProcessSnapshot_t &previous = rgSnapshots[iSnapshot];

		FILETIME ftNow;
		GetSystemTimeAsFileTime( &ftNow );
		uint64_t ulNow;
		memcpy( &ulNow, &ftNow, sizeof( ulNow ) );

		DWORD cubPids = 0;
		uint32_t cubCurrent = EnumProcesses( current.m_rgunPids, sizeof( current.m_rgunPids ), &cubPids );
		if ( cubCurrent )
		{
			qsort( current.m_rgunPids, cubPids >> 2, sizeof( DWORD ), ComparePids );
			cubCurrent = cubPids;
		}
		current.m_cPids = cubCurrent >> 2;

		uint32_t cPrevious = previous.m_cPids;
		if ( cPrevious )
		{
			uint32_t iCurrent = 0;
			for ( uint32_t iPrevious = 0;; ++iPrevious )
			{
				if ( iCurrent < current.m_cPids )
				{
					do
					{
						if ( iPrevious != previous.m_cPids &&
						     current.m_rgunPids[iCurrent] >= previous.m_rgunPids[iPrevious] )
							break;

						const DWORD unPid = current.m_rgunPids[iCurrent++];
						wchar_t wszPath[2048];
						wszPath[0] = L'\0';
						if ( s_pfnQueryFullProcessImageNameW || s_pfnGetProcessImageFileNameW )
						{
							const HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, unPid );
							if ( hProcess )
							{
								DWORD cchPath = 1024;
								if ( s_pfnQueryFullProcessImageNameW )
									s_pfnQueryFullProcessImageNameW( hProcess, PROCESS_NAME_NATIVE, wszPath, &cchPath );
								else if ( s_pfnGetProcessImageFileNameW )
									s_pfnGetProcessImageFileNameW( hProcess, wszPath, 1024 );
								CloseHandle( hProcess );
							}
						}
						WriteProcessStartEvent( ulNow, wszPath, unPid, 0, 0, &ftNow );
					} while ( iCurrent < current.m_cPids );
				}
				else if ( iPrevious >= cPrevious )
				{
					break;
				}

				for ( cPrevious = previous.m_cPids; iPrevious < cPrevious; cPrevious = previous.m_cPids )
				{
					if ( iCurrent != current.m_cPids && current.m_rgunPids[iCurrent] <= previous.m_rgunPids[iPrevious] )
						break;

					KernelProcessStop_t stop{};
					stop.m_unPid = previous.m_rgunPids[iPrevious++];
					stop.m_ulExitTime = ulNow;
					WriteProcessExitEvent( ulNow, &stop );
				}
				++iCurrent;
			}
		}

		WaitForSingleObject( s_hStopEvent, 1000 );
	}
}

// @orig: 7ebac2a4:0x10048500 (not in export)
DWORD WINAPI ThreadProcess_ProcessTrace( LPVOID )
{
	return ProcessTrace( &s_hTrace, 1, nullptr, nullptr );
}

// @orig: 7ebac2a4:0x10048520 (not in export)
DWORD WINAPI ThreadProcess( LPVOID )
{
	PollProcessList();
	return 0;
}

} // namespace

namespace ETWWin32
{

// @orig: 55 8B EC 51 8D 45 ? 50 FF 75
bool BEnumProcessIds( uint32_t cubPids, DWORD *prgunPids, uint32_t *pcubPids )
{
	DWORD cubNeeded;
	if ( !EnumProcesses( prgunPids, cubPids, &cubNeeded ) )
	{
		*pcubPids = 0;
		return false;
	}

	qsort( prgunPids, cubNeeded >> 2, sizeof( DWORD ), ComparePids );
	*pcubPids = cubNeeded;
	return cubNeeded != cubPids;
}

// @orig: 55 8B EC 83 EC ? 56 8B 75 ? 57 85 F6
bool BGetCreationTimeForPid( DWORD unPid, FILETIME *pCreationTime )
{
	const HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, unPid );
	if ( !hProcess )
	{
		pCreationTime->dwLowDateTime = 0;
		pCreationTime->dwHighDateTime = 0;
		return false;
	}

	FILETIME ftCreation;
	FILETIME ftOther;
	const bool bResult = GetProcessTimes( hProcess, &ftCreation, &ftOther, &ftOther, &ftOther ) != FALSE;
	CloseHandle( hProcess );
	*pCreationTime = ftCreation;
	return bResult;
}

// @orig: 55 8B EC 51 56 57 8B 7D
bool BGetImagePathForPid( DWORD unPid, wchar_t *pwszPath, uint32_t *pcchPath )
{
	const uint32_t cchBuffer = *pcchPath;
	*pwszPath = L'\0';
	*pcchPath = 0;
	if ( !s_pfnQueryFullProcessImageNameW && !s_pfnGetProcessImageFileNameW )
		return false;

	const HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, unPid );
	if ( !hProcess )
		return false;

	bool bResult = false;
	DWORD cchPath = cchBuffer;
	if ( s_pfnQueryFullProcessImageNameW )
	{
		bResult = s_pfnQueryFullProcessImageNameW( hProcess, PROCESS_NAME_NATIVE, pwszPath, &cchPath ) != FALSE;
	}
	else if ( s_pfnGetProcessImageFileNameW )
	{
		cchPath = s_pfnGetProcessImageFileNameW( hProcess, pwszPath, cchBuffer );
		bResult = cchPath != 0;
	}
	CloseHandle( hProcess );
	*pcchPath = cchPath + 1;
	return bResult;
}

// @orig: 7ebac2a4:0x10048130 (no unique signature)
bool BIsETWStarted()
{
	return s_bETWStarted;
}

// @orig: 55 8B EC 81 EC ? ? ? ? 56 8B 35
bool BStartETW()
{
	ResolveImagePathFunctions();
	if ( !s_pfnQueryFullProcessImageNameW && !s_pfnGetProcessImageFileNameW )
	{
		s_unErrorFlags |= EF_NO_IMAGE_PATH_API;
		return false;
	}

	OSVERSIONINFOA versionInfo;
	versionInfo.dwOSVersionInfoSize = sizeof( versionInfo );
#pragma warning( suppress : 4996 )
	if ( !GetVersionExA( &versionInfo ) )
	{
		s_unErrorFlags |= EF_NO_OS_VERSION;
		return false;
	}

	if ( versionInfo.dwMajorVersion >= 6 )
	{
		TraceProperties_t properties;
		InitTraceProperties( &properties );
		StopTraceA( 0, s_pszSessionName, &properties.m_Properties );

		InitTraceProperties( &properties );
		properties.m_Properties.Wnode.ClientContext = 2;
		properties.m_Properties.MaximumFileSize = 1024;
		properties.m_Properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
		TRACEHANDLE hSession;
		if ( StartTraceA( &hSession, s_pszSessionName, &properties.m_Properties ) != ERROR_SUCCESS )
		{
			s_unErrorFlags |= EF_START_TRACE_FAILED;
		}
		else
		{
			s_bETWStarted = true;

			EVENT_TRACE_LOGFILEA logFile;
			memset( &logFile, 0, sizeof( logFile ) );
			logFile.LoggerName = const_cast<char *>( s_pszSessionName );
			logFile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
			logFile.EventRecordCallback = EventCallback;
			s_hTrace = OpenTraceA( &logFile );
			if ( s_hTrace == 0xFFFFFFFF )
				s_unErrorFlags |= EF_OPEN_TRACE_FAILED;

			const ULONG unEnableResult =
			    EnableTrace( TRUE, 0x10, TRACE_LEVEL_INFORMATION, &k_KernelProcessGuid, hSession );
			// @note / sapdragon: this is the session handle, not a consumer one. valve's bug, CloseTrace just fails
			CloseTrace( hSession );
			if ( unEnableResult == ERROR_SUCCESS )
			{
				const HANDLE hThread = CreateThread( nullptr, 0, ThreadProcess_ProcessTrace, nullptr, 0, nullptr );
				s_unErrorFlags |= EF_TRACE_THREAD_STARTED;
				s_hThread = hThread;
				return true;
			}
			s_unErrorFlags |= EF_ENABLE_TRACE_FAILED;
		}
	}

	s_bETWStarted = true;
	s_bETWInitialised = true;
	s_hStopEvent = CreateEventA( nullptr, TRUE, FALSE, nullptr );
	if ( s_hStopEvent )
	{
		s_hThread = CreateThread( nullptr, 0, ThreadProcess, nullptr, 0, nullptr );
		if ( s_hStopEvent && s_hThread )
		{
			s_unErrorFlags |= EF_POLLING_THREAD_STARTED;
			return true;
		}
	}

	s_unErrorFlags |= EF_POLLING_THREAD_FAILED;
	return false;
}

// @orig: 55 8B EC 83 EC ? 56 8B 75 ? 85 F6 75 ? 68
void GetCurrentTimeAsEventTime( FILETIME *pEventTime )
{
	FILETIME ftNow;
	GetSystemTimeAsFileTime( &ftNow );
	*pEventTime = ftNow;
}

// @orig: 55 8B EC 83 EC ? 53 56 57 68
int NReadAvailableEvents( void *pvBuffer, uint32_t *pcubBuffer )
{
	uint32_t cubRead = 0;
	int cEvents = 0;
	EnterCriticalSection( &s_EventQueue.m_CritSec );
	for ( ; s_EventQueue.m_Buffer.GetUsed() != 0; ++cEvents )
	{
		if ( cubRead >= *pcubBuffer )
			break;

		EventHeader_t header;
		s_EventQueue.m_Buffer.Peek( &header, sizeof( header ) );
		if ( header.m_cubEvent + cubRead > *pcubBuffer )
			break;

		s_EventQueue.m_Buffer.Read( static_cast<uint8_t *>( pvBuffer ) + cubRead, header.m_cubEvent );
		cubRead += header.m_cubEvent;
	}
	LeaveCriticalSection( &s_EventQueue.m_CritSec );
	*pcubBuffer = cubRead;
	return cEvents;
}

// @note / sapdragon: only start v0 and v2 and stop v0 and v1 are known. any other version is dropped without a word
// @orig: 7ebac2a4:0x10048530 (not in export)
void WINAPI EventCallback( PEVENT_RECORD pEvent )
{
	if ( memcmp( &pEvent->EventHeader.ProviderId, &k_KernelProcessGuid, sizeof( GUID ) ) != 0 )
		return;

	const uint64_t ulTimestamp = pEvent->EventHeader.TimeStamp.QuadPart;
	switch ( MAKELONG( pEvent->EventHeader.EventDescriptor.Id, pEvent->EventHeader.EventDescriptor.Version ) )
	{
	case MAKELONG( 1, 0 ):
	{
		const auto *pStart = static_cast<const KernelProcessStartV0_t *>( pEvent->UserData );
		WriteProcessStartEvent( ulTimestamp, pStart->m_wszImageName, pStart->m_unPid, pStart->m_unParentPid,
		                        pStart->m_unSessionId, &pStart->m_ulCreationTime );
		break;
	}
	case MAKELONG( 1, 2 ):
	{
		const auto *pStart = static_cast<const KernelProcessStartV2_t *>( pEvent->UserData );
		WriteProcessStartEvent( ulTimestamp, pStart->m_wszImageName, pStart->m_unPid, pStart->m_unParentPid,
		                        pStart->m_unSessionId, &pStart->m_ulCreationTime );
		break;
	}
	case MAKELONG( 2, 0 ):
	case MAKELONG( 2, 1 ):
		WriteProcessExitEvent( ulTimestamp, static_cast<const KernelProcessStop_t *>( pEvent->UserData ) );
		break;
	}
}

// @orig: 55 8B EC 81 EC ? ? ? ? 80 3D
void StopETW()
{
	if ( !s_bETWStarted )
		return;

	if ( s_bETWInitialised )
	{
		s_bETWStarted = false;
		if ( s_hStopEvent )
			SetEvent( s_hStopEvent );
		if ( s_hThread )
			WaitForSingleObject( s_hThread, 1000 );
		s_hThread = nullptr;
		if ( s_hStopEvent )
			CloseHandle( s_hStopEvent );
		s_hStopEvent = nullptr;
	}
	else
	{
		// @note / sapdragon: s_bETWStarted stays set on this path, valve never clears it
		TraceProperties_t properties;
		InitTraceProperties( &properties );
		StopTraceA( 0, s_pszSessionName, &properties.m_Properties );
		CloseTrace( s_hTrace );
		s_hTrace = 0;
		if ( s_hThread )
			WaitForSingleObject( s_hThread, 1000 );
		s_hThread = nullptr;
	}
}

void SetSessionName( const char *pszSessionName )
{
	s_pszSessionName = pszSessionName;
}

const char *GetSessionName()
{
	return s_pszSessionName;
}

void SetStartedForStand( bool bStarted )
{
	ResolveImagePathFunctions();
	s_bETWStarted = bStarted;
	s_bETWInitialised = false;
	s_unErrorFlags = 0;
}

uint32_t GetErrorFlags()
{
	return s_unErrorFlags;
}

} // namespace ETWWin32
