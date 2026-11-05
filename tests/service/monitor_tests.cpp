// Tests for the process monitor. Compiled into service_tests, called from its main.
//
// Safety: this machine may be running the real steamservice, which owns an ETW session called "Steam Event Tracing".
// BStartETW stops any session with its own name before it starts, and a token without admin can still do that if it is
// in Performance Log Users. So the first thing RunMonitorTests does is rename the session, and it refuses to go on if
// that didn't take. Only processes spawned here are suspended, resumed or terminated. RebuildProcessNameMap and the
// polling thread do read the creation time and image path of everything they can open, that is what they are for.
#include "process_monitor/clientprocessmonitor.hpp"
#include "process_monitor/etwwin32.hpp"

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>

using ClientProcessMonitor::CClientProcessMonitor;
using ClientProcessMonitor::CMonitoredProcess;
using VacProcessMonitor::ActiveProcessData_t;
using VacProcessMonitor::EEventType;
using VacProcessMonitor::EventHeader_t;
using VacProcessMonitor::IProvider;
using VacProcessMonitor::ProcessExitEvent_t;
using VacProcessMonitor::ProcessStartEvent_t;
using VacProcessMonitor::ProviderMapping_t;

namespace
{

const char *const k_pszRealSessionName = "Steam Event Tracing";
// Fits the 20 bytes valve's properties block leaves for the name.
const char *const k_pszTestSessionName = "vac-recoded test";
// Doesn't fit, so StartTraceA refuses it whatever the token is, and nothing is created.
const char *const k_pszTooLongSessionName = "vac-recoded test session name that does not fit";

// Written out here on purpose, so a typo in the rebuild's own constant can't pass.
const GUID k_KernelProcessGuid = { 0x22FB2CD6, 0x0E7B, 0x422B, { 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 } };

constexpr uint64_t k_ulOneMinute = 600000000;

int s_cChecks = 0;
int s_cFailures = 0;
int s_iChild = 0;

#define CHECK( bCondition, ... )                                                                                       \
	do                                                                                                                 \
	{                                                                                                                  \
		++s_cChecks;                                                                                                   \
		if ( !( bCondition ) )                                                                                         \
		{                                                                                                              \
			++s_cFailures;                                                                                             \
			printf( "FAIL %s:%d %s ", __FUNCTION__, __LINE__, #bCondition );                                           \
			printf( "" __VA_ARGS__ );                                                                                  \
			printf( "\n" );                                                                                            \
		}                                                                                                              \
	} while ( 0 )

uint64_t Now()
{
	FILETIME ftNow;
	GetSystemTimeAsFileTime( &ftNow );
	uint64_t ulNow;
	memcpy( &ulNow, &ftNow, sizeof( ulNow ) );
	return ulNow;
}

uint64_t CreationTimeOf( HANDLE hProcess )
{
	FILETIME ftCreation, ftOther;
	GetProcessTimes( hProcess, &ftCreation, &ftOther, &ftOther, &ftOther );
	uint64_t ulCreation;
	memcpy( &ulCreation, &ftCreation, sizeof( ulCreation ) );
	return ulCreation;
}

// A copy of this executable that bumps a shared counter until it is killed, or gives up after two minutes.
class CChild
{
public:
	CChild()
	{
		char szMapping[64];
		snprintf( szMapping, sizeof( szMapping ), "Local\\vac_monitor_child_%lu_%d", GetCurrentProcessId(),
		          ++s_iChild );
		m_hMapping = CreateFileMappingA( INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof( LONG ), szMapping );
		m_pnCounter = static_cast<volatile LONG *>( MapViewOfFile( m_hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0 ) );

		char szExe[MAX_PATH];
		GetModuleFileNameA( nullptr, szExe, MAX_PATH );
		std::string sCommand = std::string( "\"" ) + szExe + "\" --monitor-child " + szMapping;
		STARTUPINFOA startupInfo{};
		startupInfo.cb = sizeof( startupInfo );
		PROCESS_INFORMATION info{};
		if ( CreateProcessA( szExe, sCommand.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
		                     &startupInfo, &info ) )
		{
			m_hProcess = info.hProcess;
			m_unPid = info.dwProcessId;
			CloseHandle( info.hThread );
		}
	}

	~CChild()
	{
		Kill();
		if ( m_hProcess )
			CloseHandle( m_hProcess );
		UnmapViewOfFile( const_cast<LONG *>( m_pnCounter ) );
		CloseHandle( m_hMapping );
	}

	void Kill()
	{
		if ( !m_hProcess )
			return;
		::TerminateProcess( m_hProcess, 0 );
		WaitForSingleObject( m_hProcess, 5000 );
	}

	bool BWaitForHeartbeat() const
	{
		const LONG nStart = *m_pnCounter;
		for ( int iTry = 0; iTry < 500; ++iTry )
		{
			if ( *m_pnCounter != nStart )
				return true;
			Sleep( 10 );
		}
		return false;
	}

	bool BIsFrozen() const
	{
		const LONG nStart = *m_pnCounter;
		Sleep( 300 );
		return *m_pnCounter == nStart;
	}

	HANDLE m_hProcess = nullptr;
	DWORD m_unPid = 0;

private:
	HANDLE m_hMapping = nullptr;
	volatile LONG *m_pnCounter = nullptr;
};

class CMonitorStand : public CClientProcessMonitor
{
public:
	using CClientProcessMonitor::m_cEvents;
	using CClientProcessMonitor::m_cubEvents;
	using CClientProcessMonitor::m_mapActiveProcessIdToImagePath;
	using CClientProcessMonitor::m_mapMonitoredProcesses;
	using CClientProcessMonitor::m_vecEventData;
	using CClientProcessMonitor::m_vecProcessQueue;
	using CClientProcessMonitor::PercolateDown;
	using CClientProcessMonitor::PercolateUp;
	using CClientProcessMonitor::RebuildProcessNameMap;

	CMonitoredProcess *Find( uint32_t unPid ) const
	{
		const auto it = m_mapMonitoredProcesses.find( unPid );
		return it == m_mapMonitoredProcesses.end() ? nullptr : it->second;
	}

	bool BInQueue( uint32_t unPid ) const
	{
		for ( const CMonitoredProcess *pProcess : m_vecProcessQueue )
		{
			if ( pProcess->m_unPid == unPid )
				return true;
		}
		return false;
	}

	void UnregisterAll()
	{
		while ( !m_mapMonitoredProcesses.empty() )
			UnregisterProcess( m_mapMonitoredProcesses.begin()->first );
	}
};

void Put32( std::vector<uint8_t> *pvec, size_t ib, uint32_t un )
{
	if ( pvec->size() < ib + 4 )
		pvec->resize( ib + 4 );
	memcpy( pvec->data() + ib, &un, 4 );
}

void Put64( std::vector<uint8_t> *pvec, size_t ib, uint64_t ul )
{
	if ( pvec->size() < ib + 8 )
		pvec->resize( ib + 8 );
	memcpy( pvec->data() + ib, &ul, 8 );
}

void PutString( std::vector<uint8_t> *pvec, size_t ib, const std::wstring &wsString )
{
	const size_t cub = ( wsString.size() + 1 ) * sizeof( wchar_t );
	if ( pvec->size() < ib + cub )
		pvec->resize( ib + cub );
	memcpy( pvec->data() + ib, wsString.c_str(), cub );
}

void Deliver( USHORT unId, UCHAR unVersion, uint64_t ulTimestamp, std::vector<uint8_t> *pvecUserData,
              const GUID &provider = k_KernelProcessGuid )
{
	EVENT_RECORD record{};
	record.EventHeader.ProviderId = provider;
	record.EventHeader.TimeStamp.QuadPart = static_cast<LONGLONG>( ulTimestamp );
	record.EventHeader.EventDescriptor.Id = unId;
	record.EventHeader.EventDescriptor.Version = unVersion;
	record.UserData = pvecUserData->data();
	record.UserDataLength = static_cast<USHORT>( pvecUserData->size() );
	ETWWin32::EventCallback( &record );
}

// The manifest layouts, by raw offset so they stay independent of the structs in the rebuild.
void DeliverStartV0( uint64_t ulTimestamp, uint32_t unPid, uint32_t unParent, uint32_t unSession, uint64_t ulCreation,
                     const std::wstring &wsImage )
{
	std::vector<uint8_t> vecData;
	Put32( &vecData, 0, unPid );
	Put64( &vecData, 4, ulCreation );
	Put32( &vecData, 12, unParent );
	Put32( &vecData, 16, unSession );
	PutString( &vecData, 20, wsImage );
	Deliver( 1, 0, ulTimestamp, &vecData );
}

void DeliverStartV2( uint64_t ulTimestamp, uint32_t unPid, uint32_t unParent, uint32_t unSession, uint64_t ulCreation,
                     const std::wstring &wsImage )
{
	std::vector<uint8_t> vecData;
	Put32( &vecData, 0, unPid );
	Put64( &vecData, 4, ulCreation );
	Put32( &vecData, 12, unParent );
	Put32( &vecData, 16, unSession );
	Put32( &vecData, 20, 0xAAAAAAAA );
	PutString( &vecData, 24, wsImage );
	Deliver( 1, 2, ulTimestamp, &vecData );
}

void DeliverStop( UCHAR unVersion, uint64_t ulTimestamp, uint32_t unPid, uint64_t ulCreation, uint64_t ulExit,
                  uint32_t unExitCode )
{
	std::vector<uint8_t> vecData;
	Put32( &vecData, 0, unPid );
	Put64( &vecData, 4, ulCreation );
	Put64( &vecData, 12, ulExit );
	Put32( &vecData, 20, unExitCode );
	Put32( &vecData, 24, 0x55555555 );
	Deliver( 2, unVersion, ulTimestamp, &vecData );
}

std::vector<uint8_t> ReadAllEvents( int *pcEvents = nullptr )
{
	std::vector<uint8_t> vecAll;
	std::vector<uint8_t> vecChunk( 0x10000 );
	int cEvents = 0;
	for ( ;; )
	{
		uint32_t cubChunk = static_cast<uint32_t>( vecChunk.size() );
		const int cRead = ETWWin32::NReadAvailableEvents( vecChunk.data(), &cubChunk );
		if ( !cRead )
			break;
		cEvents += cRead;
		vecAll.insert( vecAll.end(), vecChunk.begin(), vecChunk.begin() + cubChunk );
	}
	if ( pcEvents )
		*pcEvents = cEvents;
	return vecAll;
}

void StartStand()
{
	ETWWin32::SetStartedForStand( true );
	ReadAllEvents();
}

uint32_t Get32( const std::vector<uint8_t> &vec, size_t ib )
{
	uint32_t un;
	memcpy( &un, vec.data() + ib, 4 );
	return un;
}

// The wire format, against bytes laid out by hand rather than through the rebuild's structs.
void TestEventParsing()
{
	StartStand();
	const uint64_t ulTs = 0x01D9000011112222;
	const uint64_t ulCreate = 0x01D9000033334444;
	const uint64_t ulExit = 0x01D9000055556666;

	DeliverStartV0( ulTs, 0x1234, 0x5678, 7, ulCreate, L"\\Device\\a.exe" );
	int cEvents = 0;
	std::vector<uint8_t> vecRead = ReadAllEvents( &cEvents );
	CHECK( cEvents == 1, "%d", cEvents );
	CHECK( vecRead.size() == 46 + 2 * 13, "%zu", vecRead.size() );
	const uint32_t unSequence = Get32( vecRead, 4 );
	std::vector<uint8_t> vecExpected;
	Put32( &vecExpected, 0, 46 + 2 * 13 );
	Put32( &vecExpected, 4, unSequence );
	Put32( &vecExpected, 8, 1 );
	Put32( &vecExpected, 12, 1 );
	Put64( &vecExpected, 16, ulTs );
	Put32( &vecExpected, 24, 0x1234 );
	Put32( &vecExpected, 28, 0x5678 );
	Put32( &vecExpected, 32, 7 );
	Put64( &vecExpected, 36, ulCreate );
	PutString( &vecExpected, 44, L"\\Device\\a.exe" );
	CHECK( vecRead == vecExpected, "start v0 bytes" );

	DeliverStartV2( ulTs, 0x1234, 0x5678, 7, ulCreate, L"\\Device\\a.exe" );
	vecRead = ReadAllEvents( &cEvents );
	Put32( &vecExpected, 4, unSequence + 1 );
	CHECK( cEvents == 1 && vecRead == vecExpected, "start v2 skips the flags and gives the same bytes" );

	for ( const UCHAR unVersion : { 0, 1 } )
	{
		DeliverStop( unVersion, ulTs, 0x1234, ulCreate, ulExit, 0xC0000005 );
		const uint32_t unStopSequence = unSequence + 2 + unVersion;
		vecRead = ReadAllEvents( &cEvents );
		std::vector<uint8_t> vecStop;
		Put32( &vecStop, 0, 48 );
		Put32( &vecStop, 4, unStopSequence );
		Put32( &vecStop, 8, 1 );
		Put32( &vecStop, 12, 2 );
		Put64( &vecStop, 16, ulTs );
		Put32( &vecStop, 24, 0x1234 );
		Put32( &vecStop, 28, 0xC0000005 );
		Put64( &vecStop, 32, ulCreate );
		Put64( &vecStop, 40, ulExit );
		CHECK( cEvents == 1 && vecRead == vecStop, "stop v%d bytes", unVersion );
	}

	std::vector<uint8_t> vecData;
	PutString( &vecData, 24, L"ignored" );
	const GUID otherProvider = { 1, 2, 3, { 4, 5, 6, 7, 8, 9, 10, 11 } };
	Deliver( 1, 0, ulTs, &vecData, otherProvider );
	Deliver( 1, 1, ulTs, &vecData );
	Deliver( 1, 3, ulTs, &vecData );
	Deliver( 2, 2, ulTs, &vecData );
	Deliver( 3, 0, ulTs, &vecData );
	vecRead = ReadAllEvents( &cEvents );
	CHECK( cEvents == 0 && vecRead.empty(), "other providers, event ids and versions are dropped, got %d", cEvents );

	DeliverStartV0( ulTs, 1, 2, 3, ulCreate, std::wstring( 1500, L'x' ) );
	vecRead = ReadAllEvents( &cEvents );
	CHECK( cEvents == 1 && vecRead.size() == 46 + 2 * 1024, "%zu", vecRead.size() );
	CHECK( vecRead[44 + 2 * 1023] == 'x' && vecRead[44 + 2 * 1024] == 0, "a long path is cut at 1024 and terminated" );
}

void TestReadLimits()
{
	StartStand();
	const uint64_t ulTs = Now();
	DeliverStop( 0, ulTs, 1, 0, 0, 0 );
	DeliverStop( 0, ulTs, 2, 0, 0, 0 );
	DeliverStop( 0, ulTs, 3, 0, 0, 0 );

	uint8_t rgubBuffer[256];
	uint32_t cubBuffer = 47;
	CHECK( ETWWin32::NReadAvailableEvents( rgubBuffer, &cubBuffer ) == 0 && cubBuffer == 0,
	       "one byte short reads nothing" );
	cubBuffer = 100;
	CHECK( ETWWin32::NReadAvailableEvents( rgubBuffer, &cubBuffer ) == 2 && cubBuffer == 96, "only whole events" );
	cubBuffer = 0;
	CHECK( ETWWin32::NReadAvailableEvents( rgubBuffer, &cubBuffer ) == 0, "no room" );
	cubBuffer = sizeof( rgubBuffer );
	CHECK( ETWWin32::NReadAvailableEvents( rgubBuffer, &cubBuffer ) == 1 && cubBuffer == 48 );
	CHECK( Get32( std::vector<uint8_t>( rgubBuffer, rgubBuffer + 48 ), 24 ) == 3, "the third event is still in order" );

	// More than the megabyte the queue holds: the oldest go first and what is left stays readable across the wrap.
	const int cWritten = 0x100000 / 48 + 500;
	for ( int iEvent = 0; iEvent < cWritten; ++iEvent )
		DeliverStop( 0, ulTs, iEvent, 0, 0, 0 );
	int cEvents = 0;
	const std::vector<uint8_t> vecRead = ReadAllEvents( &cEvents );
	CHECK( cEvents == 0x100000 / 48, "%d", cEvents );
	CHECK( vecRead.size() == static_cast<size_t>( cEvents ) * 48 );
	bool bInOrder = true;
	for ( int iEvent = 0; iEvent < cEvents; ++iEvent )
		bInOrder &= Get32( vecRead, iEvent * 48 ) == 48 &&
		            Get32( vecRead, iEvent * 48 + 24 ) == static_cast<uint32_t>( cWritten - cEvents + iEvent );
	CHECK( bInOrder, "the newest events survive, in order" );
}

void TestProviderMapping()
{
	StartStand();
	CMonitorStand monitor;

	char szName[128];
	snprintf( szName, sizeof( szName ), "Steam_{E9FD3C51-9B58-4DA0-962C-734882B19273}_Pid:%08X",
	          GetCurrentProcessId() );
	const HANDLE hMapping = OpenFileMappingA( FILE_MAP_READ, FALSE, szName );
	CHECK( hMapping != nullptr, "%s", szName );
	if ( !hMapping )
		return;

	const auto *pMapping = static_cast<const ProviderMapping_t *>( MapViewOfFile( hMapping, FILE_MAP_READ, 0, 0, 0 ) );
	CHECK( pMapping != nullptr );
	if ( pMapping )
	{
		CHECK( *reinterpret_cast<const uint32_t *>( pMapping ) == 196612 );
		CHECK( reinterpret_cast<const uint32_t *>( pMapping )[1] ==
		           reinterpret_cast<uintptr_t>( static_cast<IProvider *>( &monitor ) ),
		       "second dword is the provider" );
		CHECK( pMapping->m_pProvider->NGetProcessCount() == 0, "callable through the mapping" );
		UnmapViewOfFile( pMapping );
	}
	CloseHandle( hMapping );
	CHECK( monitor.GetNextCallbackMicroSecs() == 0, "etw already up, the ctor doesn't schedule" );
}

void TestRefCounts()
{
	StartStand();
	CMonitorStand monitor;
	CChild child;
	CHECK( child.m_hProcess != nullptr );

	monitor.RegisterProcess( child.m_unPid );
	CHECK( monitor.NGetProcessCount() == 1 );
	CMonitoredProcess *pProcess = monitor.Find( child.m_unPid );
	CHECK( pProcess != nullptr );
	if ( !pProcess )
		return;

	CHECK( pProcess->m_cRefs == 1 );
	CHECK( pProcess->m_bHaveCreationTime );
	CHECK( pProcess->m_ulCreationTime == CreationTimeOf( child.m_hProcess ) );
	CHECK( monitor.BInQueue( child.m_unPid ) );

	monitor.RegisterProcess( child.m_unPid );
	CHECK( pProcess->m_cRefs == 2 && monitor.NGetProcessCount() == 1 && monitor.m_vecProcessQueue.size() == 1 );

	monitor.UnregisterProcess( child.m_unPid );
	CHECK( pProcess->m_cRefs == 1 && monitor.NGetProcessCount() == 1 );
	CHECK( !monitor.m_mapActiveProcessIdToImagePath.empty() );

	monitor.UnregisterProcess( child.m_unPid );
	CHECK( monitor.NGetProcessCount() == 0 && monitor.m_vecProcessQueue.empty() );
	CHECK( monitor.m_mapActiveProcessIdToImagePath.empty(), "the last one out clears the name map" );

	monitor.UnregisterProcess( child.m_unPid );
	CHECK( monitor.NGetProcessCount() == 0, "unknown pid is a no-op" );

	monitor.RegisterProcess( 0xFFFFFFF0 );
	CHECK( monitor.NGetProcessCount() == 0, "a pid with no creation time isn't kept" );
	CHECK( monitor.m_vecProcessQueue.empty() );
}

void TestProcessIds()
{
	StartStand();
	CMonitorStand monitor;
	CChild rgChildren[2];
	for ( CChild &child : rgChildren )
		monitor.RegisterProcess( child.m_unPid );

	uint32_t rgunPids[4] = { 0, 0, 0xCCCCCCCC, 0xCCCCCCCC };
	CHECK( monitor.NGetProcessIds( rgunPids, 4 ) == 2 );
	CHECK( ( rgunPids[0] == rgChildren[0].m_unPid && rgunPids[1] == rgChildren[1].m_unPid ) ||
	       ( rgunPids[0] == rgChildren[1].m_unPid && rgunPids[1] == rgChildren[0].m_unPid ) );
	CHECK( rgunPids[2] == 0xCCCCCCCC );

	rgunPids[0] = rgunPids[1] = 0;
	CHECK( monitor.NGetProcessIds( rgunPids, 1 ) == 1, "the return value is clamped" );
	CHECK( rgunPids[1] != 0, "valve's bug: the limit doesn't stop the writes" );
	monitor.UnregisterAll();
}

void TestProcessNameMap()
{
	StartStand();
	CMonitorStand monitor;
	CChild child;
	monitor.RegisterProcess( child.m_unPid );

	const ActiveProcessData_t *pData = nullptr;
	CHECK( monitor.BGetCachedProcessData( child.m_unPid, &pData ) && pData != nullptr );
	if ( pData )
	{
		CHECK( pData->m_ulCreationTime == CreationTimeOf( child.m_hProcess ) );
		CHECK( wcsstr( pData->m_pwszImagePath, L"\\Device\\" ) == pData->m_pwszImagePath, "native path" );
		CHECK( wcsstr( pData->m_pwszImagePath, L"service_tests.exe" ) != nullptr );
	}
	CHECK( monitor.BGetCachedProcessData( GetCurrentProcessId(), &pData ) && pData != nullptr,
	       "every process is in it" );
	CHECK( !monitor.BGetCachedProcessData( 0xFFFFFFF0, &pData ) && pData == nullptr );

	bool bSorted = true;
	uint32_t unLast = 0;
	for ( const auto &[unPid, data] : monitor.m_mapActiveProcessIdToImagePath )
	{
		bSorted &= unPid > unLast || unLast == 0;
		unLast = unPid;
	}
	CHECK( bSorted );

	// A dead process stays cached, so a report can still name it.
	CChild shortLived;
	monitor.RebuildProcessNameMap();
	CHECK( monitor.BGetCachedProcessData( shortLived.m_unPid, &pData ), "a new process shows up on rebuild" );
	shortLived.Kill();
	CloseHandle( shortLived.m_hProcess );
	shortLived.m_hProcess = nullptr;
	Sleep( 100 );
	monitor.RebuildProcessNameMap();
	CHECK( monitor.BGetCachedProcessData( shortLived.m_unPid, &pData ), "a dead pid is kept" );

	// A pid whose creation time changed was reused: the entry is replaced.
	const uint32_t unSelf = GetCurrentProcessId();
	auto &self = monitor.m_mapActiveProcessIdToImagePath.at( unSelf );
	const uint64_t ulRealTime = self.m_ulCreationTime;
	self.m_ulCreationTime = ulRealTime - 1;
	monitor.RebuildProcessNameMap();
	CHECK( monitor.m_mapActiveProcessIdToImagePath.at( unSelf ).m_ulCreationTime == ulRealTime,
	       "pid reuse is noticed" );

	monitor.UnregisterAll();
}

void TestTimeSort()
{
	StartStand();
	CMonitorStand monitor;

	CMonitoredProcess older( &monitor, GetCurrentProcessId() );
	CMonitoredProcess newer( &monitor, GetCurrentProcessId() );
	older.m_ulCreationTime = 100;
	newer.m_ulCreationTime = 200;
	CMonitoredProcess *pOlder = &older;
	CMonitoredProcess *pNewer = &newer;
	CHECK( CMonitoredProcess::BProcessTimeSortFunc( pNewer, pOlder ), "true when the left one is newer" );
	CHECK( !CMonitoredProcess::BProcessTimeSortFunc( pOlder, pNewer ) );
	CHECK( !CMonitoredProcess::BProcessTimeSortFunc( pOlder, pOlder ) );

	const uint64_t rgulTimes[] = { 50, 10, 90, 30, 70, 20, 80, 40, 60, 100, 5 };
	std::vector<CMonitoredProcess *> vecProcesses;
	for ( const uint64_t ulTime : rgulTimes )
	{
		auto *pProcess = new CMonitoredProcess( &monitor, GetCurrentProcessId() );
		pProcess->m_ulCreationTime = ulTime;
		vecProcesses.push_back( pProcess );
		monitor.m_vecProcessQueue.push_back( pProcess );
		monitor.PercolateUp( static_cast<int>( monitor.m_vecProcessQueue.size() ) - 1 );
		CHECK( monitor.m_vecProcessQueue[0]->m_ulCreationTime <= ulTime, "the oldest stays at the root" );
	}

	uint64_t ulLast = 0;
	while ( !monitor.m_vecProcessQueue.empty() )
	{
		const uint64_t ulRoot = monitor.m_vecProcessQueue[0]->m_ulCreationTime;
		CHECK( ulRoot >= ulLast, "%llu after %llu", ulRoot, ulLast );
		ulLast = ulRoot;
		if ( monitor.m_vecProcessQueue.size() != 1 )
			monitor.m_vecProcessQueue[0] = monitor.m_vecProcessQueue.back();
		monitor.m_vecProcessQueue.pop_back();
		monitor.PercolateDown( 0 );
	}
	CHECK( ulLast == 100 );
	for ( CMonitoredProcess *pProcess : vecProcesses )
	{
		pProcess->m_cRefs = 0;
		delete pProcess;
	}
	older.m_cRefs = newer.m_cRefs = 0;
}

void TestScheduledCallback()
{
	StartStand();
	CMonitorStand monitor;
	CChild parent;
	CChild other;
	const uint64_t ulCreation = CreationTimeOf( parent.m_hProcess );

	monitor.RegisterProcess( parent.m_unPid );
	CMonitoredProcess *pParent = monitor.Find( parent.m_unPid );
	CHECK( pParent != nullptr );
	if ( !pParent )
		return;

	// In its first five minutes a process gets every event on the machine, not only its own.
	const uint64_t ulTs = Now();
	DeliverStop( 0, ulTs, 0xFFFF0001, 0, 0, 0 );
	monitor.OnScheduledCallback();
	CHECK( monitor.NGetProcessEventCount( parent.m_unPid ) == 1 );
	CHECK( monitor.m_cEvents == 1 && monitor.m_cubEvents == 48 );
	CHECK( monitor.GetNextCallbackMicroSecs() != 0, "it reschedules itself" );

	// Its own exit reaches it through the queue and through the map, the sequence check keeps one copy.
	DeliverStop( 0, ulTs, parent.m_unPid, ulCreation, ulTs, 3 );
	monitor.OnScheduledCallback();
	CHECK( monitor.NGetProcessEventCount( parent.m_unPid ) == 2 );

	// A start whose parent is monitored registers the child, deferred until the callback is done.
	DeliverStartV2( ulTs, other.m_unPid, parent.m_unPid, 1, ulCreation, L"\\Device\\child.exe" );
	monitor.OnScheduledCallback();
	CHECK( monitor.NGetProcessEventCount( parent.m_unPid ) == 3 );
	CMonitoredProcess *pChild = monitor.Find( other.m_unPid );
	CHECK( pChild != nullptr, "the child is followed" );
	CHECK( pParent->m_vecChildPids.size() == 1 && pParent->m_vecChildPids[0] == other.m_unPid );
	CHECK( monitor.NGetProcessCount() == 2 );
	if ( pChild )
		CHECK( monitor.NGetProcessEventCount( other.m_unPid ) == 3, "registering replays the cache, got %d",
		       monitor.NGetProcessEventCount( other.m_unPid ) );

	// What NGetNewEvents hands out: raw events, then pointers to the service's copies.
	uint8_t rgubBuffer[512];
	const EventHeader_t *const *prgpEvents = nullptr;
	uint32_t cEvents = monitor.NGetNewEvents( parent.m_unPid, &prgpEvents, 0, rgubBuffer, sizeof( rgubBuffer ) );
	const uint32_t cubExpected = 48 + 48 + 46 + 2 * 17;
	CHECK( cEvents == 3, "%u", cEvents );
	CHECK( reinterpret_cast<const uint8_t *>( prgpEvents ) == rgubBuffer + cubExpected );
	CHECK( prgpEvents[0] == pParent->m_vecEventHeaders[0] && prgpEvents[2] == pParent->m_vecEventHeaders[2] );
	CHECK( !memcmp( rgubBuffer, pParent->m_vecEventData.data(), cubExpected ) );
	CHECK( reinterpret_cast<const EventHeader_t *>( rgubBuffer )->m_cubEvent == 48 );

	cEvents = monitor.NGetNewEvents( parent.m_unPid, &prgpEvents, 2, rgubBuffer, sizeof( rgubBuffer ) );
	CHECK( cEvents == 1 && prgpEvents[0] == pParent->m_vecEventHeaders[2], "start index" );
	cEvents = monitor.NGetNewEvents( parent.m_unPid, &prgpEvents, 3, rgubBuffer, sizeof( rgubBuffer ) );
	CHECK( cEvents == 0 && reinterpret_cast<const uint8_t *>( prgpEvents ) == rgubBuffer, "nothing new" );
	cEvents = monitor.NGetNewEvents( parent.m_unPid, &prgpEvents, 0, rgubBuffer, 48 + 4 );
	CHECK( cEvents == 1, "room for one event plus its pointer" );
	cEvents = monitor.NGetNewEvents( parent.m_unPid, &prgpEvents, 0, rgubBuffer, 48 + 3 );
	CHECK( cEvents == 0, "no room for the pointer" );
	cEvents = monitor.NGetNewEvents( 0xFFFF0002, &prgpEvents, 0, rgubBuffer, sizeof( rgubBuffer ) );
	CHECK( cEvents == 0 && prgpEvents == nullptr, "unknown pid" );

	// Past five minutes a process only hears about itself and its children, and leaves the queue.
	const int cBefore = monitor.NGetProcessEventCount( parent.m_unPid );
	const uint64_t ulLater = ulCreation + 6 * k_ulOneMinute;
	DeliverStop( 0, ulLater, 0xFFFF0003, 0, 0, 0 );
	monitor.OnScheduledCallback();
	CHECK( !monitor.BInQueue( parent.m_unPid ), "dropped from the queue" );
	CHECK( monitor.NGetProcessEventCount( parent.m_unPid ) == cBefore, "strangers don't reach it any more" );
	DeliverStop( 0, ulLater, parent.m_unPid, ulCreation, ulLater, 0 );
	monitor.OnScheduledCallback();
	CHECK( monitor.NGetProcessEventCount( parent.m_unPid ) == cBefore + 1, "its own events still do" );

	// Dropping the parent takes the child's reference with it.
	monitor.UnregisterProcess( parent.m_unPid );
	CHECK( monitor.Find( other.m_unPid ) == nullptr, "child unregistered with its parent" );
	CHECK( monitor.NGetProcessCount() == 0 );
}

void TestEventCache()
{
	StartStand();
	CMonitorStand monitor;
	CChild child;
	const uint64_t ulTs = Now();

	// Cached with nobody registered, handed over on register.
	DeliverStop( 0, ulTs, 0xFFFF0001, 0, 0, 0 );
	DeliverStop( 0, ulTs, 0xFFFF0002, 0, 0, 0 );
	monitor.OnScheduledCallback();
	CHECK( monitor.m_cEvents == 2 );
	monitor.RegisterProcess( child.m_unPid );
	CHECK( monitor.NGetProcessEventCount( child.m_unPid ) == 2, "the cache is replayed" );
	monitor.UnregisterAll();

	// The expiry walk stops at the first fresh event, so a stale one behind fresh ones stays.
	DeliverStop( 0, Now() - 6 * k_ulOneMinute, 0xFFFF0003, 0, 0, 0 );
	monitor.OnScheduledCallback();
	CHECK( monitor.m_cEvents == 3, "%u", monitor.m_cEvents );
	monitor.OnScheduledCallback();
	CHECK( monitor.m_cEvents == 3, "%u", monitor.m_cEvents );

	// At the front it goes in the same callback: any read makes the loop run again, and that pass expires it.
	CMonitorStand clean;
	DeliverStop( 0, Now() - 6 * k_ulOneMinute, 0xFFFF0004, 0, 0, 0 );
	clean.OnScheduledCallback();
	CHECK( clean.m_cEvents == 0 && clean.m_cubEvents == 0, "the stale one is gone, got %u", clean.m_cEvents );
	DeliverStop( 0, Now(), 0xFFFF0005, 0, 0, 0 );
	clean.OnScheduledCallback();
	CHECK( clean.m_cEvents == 1 && clean.m_cubEvents == 48, "a fresh one stays, got %u", clean.m_cEvents );

	// The cache grows in 4096 steps once less than 1024 bytes are free.
	CMonitorStand grower;
	CHECK( grower.m_vecEventData.size() == 4096 );
	const uint64_t ulFresh = Now();
	for ( int iEvent = 0; iEvent < 70; ++iEvent )
		DeliverStop( 0, ulFresh, 0xFFFF1000 + iEvent, 0, 0, 0 );
	grower.OnScheduledCallback();
	CHECK( grower.m_cEvents == 70, "%u", grower.m_cEvents );
	CHECK( grower.m_vecEventData.size() % 4096 == 0 && grower.m_vecEventData.size() > 4096, "%zu",
	       grower.m_vecEventData.size() );

	// A monitored process grows in 1024 steps, its pointers follow and the size reported is the allocation.
	CChild big;
	grower.RegisterProcess( big.m_unPid );
	const int cReplayed = grower.NGetProcessEventCount( big.m_unPid );
	CHECK( cReplayed == 70, "%d", cReplayed );
	const int cubAllocated = grower.NGetProcessEventMemorySize( big.m_unPid );
	CHECK( cubAllocated % 1024 == 0 && cubAllocated >= 70 * 48, "%d", cubAllocated );
	CMonitoredProcess *pBig = grower.Find( big.m_unPid );
	if ( pBig )
	{
		bool bPointersGood = true;
		for ( int iEvent = 0; iEvent < cReplayed; ++iEvent )
		{
			const auto *pExpected =
			    reinterpret_cast<const EventHeader_t *>( pBig->m_vecEventData.data() + iEvent * 48 );
			bPointersGood &= pBig->m_vecEventHeaders[iEvent] == pExpected;
			bPointersGood &= pExpected->m_eType == EEventType::ProcessExit;
		}
		CHECK( bPointersGood, "headers rebased after growth" );
	}
	CHECK( grower.NGetProcessEventMemorySize( 0xFFFF0002 ) == 0 );
	CHECK( grower.NGetProcessEventCount( 0xFFFF0002 ) == 0 );
	grower.UnregisterAll();
}

// Valve's suspend is a debug attach, so both calls have to come from this thread and the child is ours.
void TestSuspendResumeTerminate()
{
	StartStand();
	CMonitorStand monitor;
	CChild child;
	CHECK( child.m_hProcess != nullptr );
	if ( !child.m_hProcess )
		return;

	CHECK( child.BWaitForHeartbeat(), "the child runs" );

	CHECK( monitor.SuspendProcess( child.m_unPid ), "%lu", GetLastError() );
	CHECK( child.BIsFrozen(), "suspended means no heartbeat" );
	CHECK( monitor.ResumeProcess( child.m_unPid ), "%lu", GetLastError() );
	CHECK( child.BWaitForHeartbeat(), "resumed means the heartbeat is back" );

	CHECK( WaitForSingleObject( child.m_hProcess, 0 ) == WAIT_TIMEOUT, "still alive" );
	CHECK( monitor.TerminateProcess( child.m_unPid ) );
	CHECK( WaitForSingleObject( child.m_hProcess, 5000 ) == WAIT_OBJECT_0, "gone" );
	DWORD unExitCode = 1;
	GetExitCodeProcess( child.m_hProcess, &unExitCode );
	CHECK( unExitCode == 0, "valve exits it with 0, got %lu", unExitCode );

	CHECK( !monitor.TerminateProcess( child.m_unPid ), "already dead" );
	CHECK( !monitor.SuspendProcess( child.m_unPid ), "already dead" );
	CHECK( !monitor.ResumeProcess( child.m_unPid ), "nothing attached" );
}

void TestTimeAndEnumHelpers()
{
	FILETIME ftEvent;
	const uint64_t ulBefore = Now();
	ETWWin32::GetCurrentTimeAsEventTime( &ftEvent );
	uint64_t ulEvent;
	memcpy( &ulEvent, &ftEvent, sizeof( ulEvent ) );
	CHECK( ulEvent >= ulBefore && ulEvent - ulBefore < 10 * k_ulOneMinute, "system time" );

	DWORD rgunPids[1024];
	uint32_t cubPids = 0;
	CHECK( ETWWin32::BEnumProcessIds( sizeof( rgunPids ), rgunPids, &cubPids ), "the buffer wasn't full" );
	bool bSorted = true;
	bool bFoundSelf = false;
	for ( uint32_t iPid = 0; iPid < cubPids / 4; ++iPid )
	{
		bSorted &= iPid == 0 || rgunPids[iPid - 1] < rgunPids[iPid];
		bFoundSelf |= rgunPids[iPid] == GetCurrentProcessId();
	}
	CHECK( bSorted && bFoundSelf );
	cubPids = 8;
	CHECK( !ETWWin32::BEnumProcessIds( 8, rgunPids, &cubPids ) && cubPids == 8, "a full buffer returns false" );

	FILETIME ftCreation;
	CHECK( ETWWin32::BGetCreationTimeForPid( GetCurrentProcessId(), &ftCreation ) );
	CHECK( !ETWWin32::BGetCreationTimeForPid( 0xFFFFFFF0, &ftCreation ) );
	CHECK( ftCreation.dwLowDateTime == 0 && ftCreation.dwHighDateTime == 0, "zeroed on failure" );

	ETWWin32::SetStartedForStand( true );
	wchar_t wszPath[1024];
	uint32_t cchPath = ARRAYSIZE( wszPath );
	CHECK( ETWWin32::BGetImagePathForPid( GetCurrentProcessId(), wszPath, &cchPath ) );
	CHECK( cchPath == wcslen( wszPath ) + 1, "the count includes the terminator" );
	cchPath = ARRAYSIZE( wszPath );
	CHECK( !ETWWin32::BGetImagePathForPid( 0xFFFFFFF0, wszPath, &cchPath ) && cchPath == 0 );
}

bool BQuerySession( const char *pszName )
{
	struct
	{
		EVENT_TRACE_PROPERTIES m_Properties;
		char m_szName[256];
	} properties{};
	properties.m_Properties.Wnode.BufferSize = sizeof( properties );
	properties.m_Properties.LoggerNameOffset = offsetof( decltype( properties ), m_szName );
	return ControlTraceA( 0, pszName, &properties.m_Properties, EVENT_TRACE_CONTROL_QUERY ) == ERROR_SUCCESS;
}

void StopTestSession( const char *pszName )
{
	struct
	{
		EVENT_TRACE_PROPERTIES m_Properties;
		char m_szName[256];
	} properties{};
	properties.m_Properties.Wnode.BufferSize = sizeof( properties );
	properties.m_Properties.LoggerNameOffset = offsetof( decltype( properties ), m_szName );
	ControlTraceA( 0, pszName, &properties.m_Properties, EVENT_TRACE_CONTROL_STOP );
}

// Looks through the live queue for this pid's start and exit, for up to five seconds.
bool BWaitForEvent( uint32_t unPid, EEventType eType, std::vector<uint8_t> *pvecEvent )
{
	for ( int iTry = 0; iTry < 50; ++iTry )
	{
		const std::vector<uint8_t> vecRead = ReadAllEvents();
		for ( size_t ib = 0; ib < vecRead.size(); ib += Get32( vecRead, ib ) )
		{
			if ( Get32( vecRead, ib + 12 ) == static_cast<uint32_t>( eType ) && Get32( vecRead, ib + 24 ) == unPid )
			{
				pvecEvent->assign( vecRead.begin() + ib, vecRead.begin() + ib + Get32( vecRead, ib ) );
				return true;
			}
		}
		Sleep( 100 );
	}
	return false;
}

// StartTraceA can't take the name, which is the same road a token without the rights goes down: the ctor still comes
// up, on the polling thread. Then a real child through that thread, end to end.
void TestStartTraceFailureFallsBackToPolling()
{
	ETWWin32::SetStartedForStand( false );
	ETWWin32::SetSessionName( k_pszTooLongSessionName );
	ReadAllEvents();
	{
		CMonitorStand monitor;
		const uint32_t unFlags = ETWWin32::GetErrorFlags();
		CHECK( ETWWin32::BIsETWStarted() );
		CHECK( unFlags & ETWWin32::EF_START_TRACE_FAILED, "flags %x", unFlags );
		CHECK( unFlags & ETWWin32::EF_POLLING_THREAD_STARTED, "flags %x", unFlags );
		CHECK( !( unFlags & ETWWin32::EF_TRACE_THREAD_STARTED ), "flags %x", unFlags );
		CHECK( monitor.GetNextCallbackMicroSecs() != 0, "the fallback counts as started and schedules" );

		Sleep( 1500 );
		CChild child;
		std::vector<uint8_t> vecEvent;
		CHECK( BWaitForEvent( child.m_unPid, EEventType::ProcessStart, &vecEvent ), "the poll sees the start" );
		if ( !vecEvent.empty() )
		{
			CHECK( Get32( vecEvent, 28 ) == 0, "polling has no parent" );
			const std::wstring wsPath( reinterpret_cast<const wchar_t *>( vecEvent.data() + 44 ) );
			CHECK( wsPath.find( L"service_tests.exe" ) != std::wstring::npos, "and reads the path" );
		}
		const uint32_t unPid = child.m_unPid;
		child.Kill();
		CHECK( BWaitForEvent( unPid, EEventType::ProcessExit, &vecEvent ), "the poll sees the exit" );
		if ( !vecEvent.empty() )
			CHECK( Get32( vecEvent, 28 ) == 0, "polling has no exit code" );

		monitor.Shutdown();
		CHECK( !ETWWin32::BIsETWStarted(), "polling path clears the flag" );
		monitor.UnregisterAll();
	}
	CHECK( !BQuerySession( k_pszTooLongSessionName ), "nothing was left behind" );
}

// A real session under our own name. Whether it starts depends on the token, both ways are fine, the report says which.
void TestOwnSession()
{
	ETWWin32::SetStartedForStand( false );
	ETWWin32::SetSessionName( k_pszTestSessionName );
	ReadAllEvents();
	StopTestSession( k_pszTestSessionName );

	const bool bStarted = ETWWin32::BStartETW();
	const uint32_t unFlags = ETWWin32::GetErrorFlags();
	CHECK( bStarted, "flags %x", unFlags );
	CHECK( ETWWin32::BIsETWStarted() );

	if ( unFlags & ETWWin32::EF_TRACE_THREAD_STARTED )
	{
		printf( "monitor: own ETW session started under this token, flags %x\n", unFlags );
		CHECK( BQuerySession( k_pszTestSessionName ), "the session exists" );
		Sleep( 500 );
		CChild child;
		const uint32_t unPid = child.m_unPid;
		std::vector<uint8_t> vecEvent;
		const bool bSawStart = BWaitForEvent( unPid, EEventType::ProcessStart, &vecEvent );
		printf( "monitor: real ETW start event for a child: %s\n",
		        bSawStart ? "seen" : "NOT seen, this Windows sends a version valve doesn't parse" );
		if ( bSawStart )
			CHECK( Get32( vecEvent, 28 ) == GetCurrentProcessId(), "real ETW has the parent" );
		child.Kill();
		const bool bSawExit = BWaitForEvent( unPid, EEventType::ProcessExit, &vecEvent );
		printf( "monitor: real ETW exit event for a child: %s\n", bSawExit ? "seen" : "NOT seen" );
		ETWWin32::StopETW();
		CHECK( !BQuerySession( k_pszTestSessionName ), "StopETW stopped it" );
		CHECK( ETWWin32::BIsETWStarted(), "valve's bug: this path never clears the flag" );
	}
	else
	{
		printf( "monitor: own ETW session did not start under this token, flags %x, polling instead\n", unFlags );
		CHECK( unFlags & ( ETWWin32::EF_START_TRACE_FAILED | ETWWin32::EF_ENABLE_TRACE_FAILED ), "flags %x", unFlags );
		CHECK( unFlags & ETWWin32::EF_POLLING_THREAD_STARTED, "flags %x", unFlags );
		ETWWin32::StopETW();
		CHECK( !ETWWin32::BIsETWStarted() );
	}

	StopTestSession( k_pszTestSessionName );
	ETWWin32::SetStartedForStand( false );
	ReadAllEvents();
}

} // namespace

int RunMonitorChild( const char *pszMappingName )
{
	const HANDLE hMapping = OpenFileMappingA( FILE_MAP_ALL_ACCESS, FALSE, pszMappingName );
	if ( !hMapping )
		return 1;
	auto *pnCounter = static_cast<volatile LONG *>( MapViewOfFile( hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0 ) );
	if ( !pnCounter )
		return 1;

	const ULONGLONG ulStart = GetTickCount64();
	while ( GetTickCount64() - ulStart < 120000 )
	{
		InterlockedIncrement( pnCounter );
		Sleep( 1 );
	}
	return 0;
}

void RunMonitorTests( int *pcChecks, int *pcFailures )
{
	ETWWin32::SetSessionName( k_pszTestSessionName );
	if ( !strcmp( ETWWin32::GetSessionName(), k_pszRealSessionName ) )
	{
		printf( "FAIL refusing to run the monitor under the real session name\n" );
		++*pcChecks;
		++*pcFailures;
		return;
	}
	const bool bRealSessionBefore = BQuerySession( k_pszRealSessionName );

	TestEventParsing();
	TestReadLimits();
	TestProviderMapping();
	TestRefCounts();
	TestProcessIds();
	TestProcessNameMap();
	TestTimeSort();
	TestScheduledCallback();
	TestEventCache();
	TestSuspendResumeTerminate();
	TestTimeAndEnumHelpers();
	TestStartTraceFailureFallsBackToPolling();
	TestOwnSession();

	if ( bRealSessionBefore )
		CHECK( BQuerySession( k_pszRealSessionName ), "the real steam session must survive this" );
	printf( "monitor: real steam session visible to this token: %s\n", bRealSessionBefore ? "yes, left alone" : "no" );

	ETWWin32::SetStartedForStand( true );
	*pcChecks += s_cChecks;
	*pcFailures += s_cFailures;
}
