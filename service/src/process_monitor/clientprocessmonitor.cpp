// @binary: 7ebac2a4
#include "process_monitor/clientprocessmonitor.hpp"
#include "process_monitor/etwwin32.hpp"

#include <cstdlib>
#include <cstring>
#include <utility>

using VacProcessMonitor::ActiveProcessData_t;
using VacProcessMonitor::EEventType;
using VacProcessMonitor::EventHeader_t;
using VacProcessMonitor::ProcessStartEvent_t;

namespace
{

constexpr int64_t k_nEventWindow = 3000000000;

void GrowEventData( std::vector<uint8_t> *pvecData, uint32_t cubGrowStep, uint32_t cubGrow )
{
	const uint32_t cubLast = static_cast<uint32_t>( pvecData->size() ) + cubGrow - 1;
	pvecData->resize( cubGrowStep + cubLast - cubLast % cubGrowStep );
}

uint64_t CurrentEventTime()
{
	FILETIME ftNow;
	ETWWin32::GetCurrentTimeAsEventTime( &ftNow );
	uint64_t ulNow;
	memcpy( &ulNow, &ftNow, sizeof( ulNow ) );
	return ulNow;
}

const EventHeader_t *NextEvent( const EventHeader_t *pEvent )
{
	return reinterpret_cast<const EventHeader_t *>( reinterpret_cast<const uint8_t *>( pEvent ) + pEvent->m_cubEvent );
}

// @orig: 7ebac2a4:0x100A0030 (no unique signature)
bool ResumeProcessById( DWORD unPid )
{
	return DebugActiveProcessStop( unPid ) != FALSE;
}

// @orig: 7ebac2a4:0x100A0120 (no unique signature)
bool SuspendProcessById( DWORD unPid )
{
	return DebugActiveProcess( unPid ) != FALSE;
}

// @orig: 55 8B EC 53 56 FF 75 ? 32 DB 6A ? 6A
bool TerminateProcessById( DWORD unPid, UINT unExitCode )
{
	bool bResult = false;
	const HANDLE hProcess = OpenProcess( PROCESS_TERMINATE, FALSE, unPid );
	if ( hProcess )
	{
		bResult = ::TerminateProcess( hProcess, unExitCode ) != FALSE;
		CloseHandle( hProcess );
	}
	return bResult;
}

} // namespace

namespace ClientProcessMonitor
{

// @orig: inlined
CMonitoredProcess::CMonitoredProcess( CClientProcessMonitor *pMonitor, uint32_t unPid )
{
	m_cRefs = 1;
	m_pMonitor = pMonitor;
	m_unPid = unPid;
	m_unLastSequence = 0xFFFFFFFF;
	m_cubEvents = 0;
	m_vecEventData.resize( 1024 );
	m_bHaveCreationTime =
	    ETWWin32::BGetCreationTimeForPid( m_unPid, reinterpret_cast<FILETIME *>( &m_ulCreationTime ) );
}

// @orig: 7ebac2a4:0x10058F10 (not in export)
CMonitoredProcess::~CMonitoredProcess()
{
	for ( size_t iChild = 0; iChild < m_vecChildPids.size(); ++iChild )
		m_pMonitor->UnregisterProcess( m_vecChildPids[iChild] );
	m_vecChildPids.clear();
}

// @orig: 56 8B F1 8B 46 ? 85 C0 7E
int CMonitoredProcess::Release()
{
	const uint32_t cRefs = m_cRefs - 1;
	if ( cRefs > 0xFFFFFE )
		return 0;

	m_cRefs = cRefs;
	if ( cRefs != 0 )
		return cRefs;

	OnFinalRelease();
	return 0;
}

// @orig: 55 8B EC 83 EC ? 53 8B 5D ? 57 8B F9 83 7F
void CMonitoredProcess::AddNewEvent( const EventHeader_t *pEvent )
{
	if ( m_cubEvents != 0 && pEvent->m_unSequence == m_unLastSequence )
		return;

	if ( m_vecEventData.size() < pEvent->m_cubEvent + m_cubEvents )
	{
		const uintptr_t ulOldBase = reinterpret_cast<uintptr_t>( m_vecEventData.data() );
		GrowEventData( &m_vecEventData, 1024, pEvent->m_cubEvent );
		const uintptr_t ulNewBase = reinterpret_cast<uintptr_t>( m_vecEventData.data() );
		if ( ulOldBase != ulNewBase )
		{
			for ( const EventHeader_t *&pHeader : m_vecEventHeaders )
				pHeader = reinterpret_cast<const EventHeader_t *>( reinterpret_cast<uintptr_t>( pHeader ) - ulOldBase +
				                                                   ulNewBase );
		}
	}

	uint8_t *pubEvent = m_vecEventData.data() + m_cubEvents;
	memcpy( pubEvent, pEvent, pEvent->m_cubEvent );
	m_vecEventHeaders.push_back( reinterpret_cast<const EventHeader_t *>( pubEvent ) );
	m_cubEvents += pEvent->m_cubEvent;
	m_unLastSequence = pEvent->m_unSequence;

	if ( pEvent->m_eType != EEventType::ProcessStart )
		return;

	const auto *pStart = reinterpret_cast<const ProcessStartEvent_t *>( pEvent );
	if ( pStart->m_unParentPid == m_unPid )
	{
		m_pMonitor->RegisterProcess( pStart->m_unPid );
		m_vecChildPids.push_back( pStart->m_unPid );
	}
}

// @orig: 55 8B EC 80 79 ? ? 75
int CMonitoredProcess::NCompareEventTime( uint64_t ulTime ) const
{
	if ( !m_bHaveCreationTime )
		return 0;

	const int64_t nDelta = static_cast<int64_t>( ulTime - m_ulCreationTime );
	if ( _abs64( nDelta ) <= k_nEventWindow )
		return 0;
	return nDelta <= 0 ? -1 : 1;
}

// @orig: 7ebac2a4:0x10059280 (not in export)
bool CMonitoredProcess::BProcessTimeSortFunc( CMonitoredProcess *const &pLeft, CMonitoredProcess *const &pRight )
{
	return pLeft->m_ulCreationTime > pRight->m_ulCreationTime;
}

// @orig: 55 8B EC 51 53 56 57 8B F9 8D 4F
CClientProcessMonitor::CClientProcessMonitor()
{
	m_cEvents = 0;
	m_cubEvents = 0;
	m_vecEventData.resize( 4096 );
	m_bInCallback = false;
	m_ulNextCallbackMicroSecs = 0;
	InitializeCriticalSection( &m_CritSec );
	if ( !ETWWin32::BIsETWStarted() && ETWWin32::BStartETW() )
		Schedule( 1000000 );
}

void CClientProcessMonitor::Schedule( uint32_t unMicroSecs )
{
	m_ulNextCallbackMicroSecs = GetTickCount64() * 1000 + unMicroSecs;
}

// @orig: 7ebac2a4:0x10058FB0 (not in export)
void CClientProcessMonitor::AddDeferredOperation( uint32_t unPid, bool bRegister )
{
	if ( m_bInCallback )
		m_vecDeferredOperations.push_back( { bRegister, unPid } );
}

// @orig: 7ebac2a4:0x10059D20 (not in export)
int CClientProcessMonitor::PercolateUp( int iElement )
{
	int iCurrent = iElement;
	if ( iElement < static_cast<int>( m_vecProcessQueue.size() ) && iElement != 0 )
	{
		int iParent;
		do
		{
			iParent = ( iCurrent + 1 ) / 2 - 1;
			if ( CMonitoredProcess::BProcessTimeSortFunc( m_vecProcessQueue[iCurrent], m_vecProcessQueue[iParent] ) )
				break;

			std::swap( m_vecProcessQueue[iParent], m_vecProcessQueue[iCurrent] );
			iCurrent = iParent;
		} while ( iParent != 0 );
	}
	return iCurrent;
}

// @orig: 7ebac2a4:0x10059C70 (not in export)
int CClientProcessMonitor::PercolateDown( int iElement )
{
	const int cElements = static_cast<int>( m_vecProcessQueue.size() );
	int iCurrent = iElement;
	int iBest = iElement;
	if ( iElement >= cElements / 2 )
		return iElement;

	do
	{
		const int iLeft = 2 * iCurrent + 1;
		if ( iLeft < cElements &&
		     CMonitoredProcess::BProcessTimeSortFunc( m_vecProcessQueue[iCurrent], m_vecProcessQueue[iLeft] ) )
			iBest = iLeft;

		const int iRight = 2 * iCurrent + 2;
		if ( iRight < cElements &&
		     CMonitoredProcess::BProcessTimeSortFunc( m_vecProcessQueue[iBest], m_vecProcessQueue[iRight] ) )
			iBest = iRight;

		if ( iBest == iCurrent )
			break;

		std::swap( m_vecProcessQueue[iCurrent], m_vecProcessQueue[iBest] );
		iCurrent = iBest;
	} while ( iBest < cElements / 2 );
	return iCurrent;
}

// @orig: 55 8B EC 51 53 56 57 8B F9 8D B7 ? ? ? ? 56 FF 15 ? ? ? ? 8B 87
bool CClientProcessMonitor::BGetCachedProcessData( uint32_t unPid, const ActiveProcessData_t **ppData )
{
	EnterCriticalSection( &m_CritSec );
	const auto it = m_mapActiveProcessIdToImagePath.find( unPid );
	const bool bFound = it != m_mapActiveProcessIdToImagePath.end();
	*ppData = bFound ? &it->second : nullptr;
	LeaveCriticalSection( &m_CritSec );
	return bFound;
}

// @note / sapdragon: the output is the raw events and then an array of pointers to the service's own copies of them,
// not to the ones in the output. *pprgpEvents points at that array. that's how valve hands it out
// @orig: 55 8B EC 51 56 57 8B F9 8D B7
uint32_t CClientProcessMonitor::NGetNewEvents( uint32_t unPid, const EventHeader_t *const **pprgpEvents,
                                               int nStartEvent, void *pvBuffer, uint32_t cubBuffer )
{
	EnterCriticalSection( &m_CritSec );
	const auto it = m_mapMonitoredProcesses.find( unPid );
	if ( it == m_mapMonitoredProcesses.end() )
	{
		*pprgpEvents = nullptr;
		LeaveCriticalSection( &m_CritSec );
		return 0;
	}

	const CMonitoredProcess *pProcess = it->second;
	const int cHeaders = static_cast<int>( pProcess->m_vecEventHeaders.size() );
	const EventHeader_t *const *prgpHeaders =
	    pProcess->m_bHaveCreationTime && nStartEvent < cHeaders ? &pProcess->m_vecEventHeaders[nStartEvent] : nullptr;

	const uint32_t cAvailable = cHeaders - nStartEvent;
	uint8_t *pubOutput = static_cast<uint8_t *>( pvBuffer );
	uint32_t cCopied = 0;
	if ( cAvailable )
	{
		uint32_t cubUsed = 0;
		do
		{
			const EventHeader_t *pHeader = prgpHeaders[cCopied];
			const uint32_t cubEvent = pHeader->m_cubEvent;
			const uint32_t cubNeeded = cubEvent + cubUsed + 4;
			if ( cubNeeded > cubBuffer )
				break;

			memcpy( pubOutput, pHeader, cubEvent );
			cubUsed = cubNeeded;
			++cCopied;
			pubOutput += cubEvent;
		} while ( cCopied < cAvailable );
	}

	*pprgpEvents = reinterpret_cast<const EventHeader_t *const *>( pubOutput );
	if ( cCopied )
		memcpy( pubOutput, prgpHeaders, 4 * cCopied );
	LeaveCriticalSection( &m_CritSec );
	return cCopied;
}

// @orig: 56 57 8B F9 8D B7 ? ? ? ? 56 FF 15 ? ? ? ? 8B BF
int CClientProcessMonitor::NGetProcessCount()
{
	EnterCriticalSection( &m_CritSec );
	const int cProcesses = static_cast<int>( m_mapMonitoredProcesses.size() );
	LeaveCriticalSection( &m_CritSec );
	return cProcesses;
}

// @orig: 55 8B EC 56 57 8B F9 8D B7 ? ? ? ? 56 FF 15 ? ? ? ? 8D 45 ? 50 8D 4F ? E8 ? ? ? ? 83 F8
int CClientProcessMonitor::NGetProcessEventCount( uint32_t unPid )
{
	EnterCriticalSection( &m_CritSec );
	const auto it = m_mapMonitoredProcesses.find( unPid );
	if ( it == m_mapMonitoredProcesses.end() )
	{
		LeaveCriticalSection( &m_CritSec );
		return 0;
	}

	const int cEvents = static_cast<int>( it->second->m_vecEventHeaders.size() );
	LeaveCriticalSection( &m_CritSec );
	return cEvents;
}

// @note / sapdragon: this is the allocation, not the bytes in use. valve's, keep it
// @orig: 55 8B EC 56 57 8B F9 8D B7 ? ? ? ? 56 FF 15 ? ? ? ? 8D 45 ? 50 8D 4F ? E8 ? ? ? ? 3B 87
int CClientProcessMonitor::NGetProcessEventMemorySize( uint32_t unPid )
{
	EnterCriticalSection( &m_CritSec );
	const auto it = m_mapMonitoredProcesses.find( unPid );
	if ( it == m_mapMonitoredProcesses.end() )
	{
		LeaveCriticalSection( &m_CritSec );
		return 0;
	}

	const int cubMemory = static_cast<int>( it->second->m_vecEventData.size() );
	LeaveCriticalSection( &m_CritSec );
	return cubMemory;
}

// @note / sapdragon: cPids only limits the return value, every id still gets written. valve's overflow, keep it.
// the order is whatever unordered_map gives, valve's is CUtlHashMap slot order
// @orig: 55 8B EC 53 8B D9 56 8D B3
uint32_t CClientProcessMonitor::NGetProcessIds( uint32_t *prgunPids, uint32_t cPids )
{
	EnterCriticalSection( &m_CritSec );
	const uint32_t cProcesses = static_cast<uint32_t>( m_mapMonitoredProcesses.size() );
	const uint32_t cReturned = cPids < cProcesses ? cPids : cProcesses;
	for ( const auto &[unPid, pProcess] : m_mapMonitoredProcesses )
		*prgunPids++ = unPid;
	LeaveCriticalSection( &m_CritSec );
	return cReturned;
}

// @orig: 55 8B EC 83 EC ? 53 8B D9 56 57 8D B3
void CClientProcessMonitor::OnScheduledCallback()
{
	EnterCriticalSection( &m_CritSec );
	m_bInCallback = true;

	uint32_t cubRead;
	do
	{
		const uint64_t ulOldest = CurrentEventTime() - k_nEventWindow;
		const EventHeader_t *pKeep = reinterpret_cast<const EventHeader_t *>( m_vecEventData.data() );
		uint32_t iEvent = 0;
		for ( ; iEvent < m_cEvents; ++iEvent )
		{
			if ( pKeep->m_ulTimestamp >= ulOldest )
				break;
			pKeep = NextEvent( pKeep );
		}

		const uint32_t cubDropped =
		    static_cast<uint32_t>( reinterpret_cast<const uint8_t *>( pKeep ) - m_vecEventData.data() );
		// @note / sapdragon: V_memcpy in the original, which copes with overlap
		if ( cubDropped && m_cubEvents != cubDropped )
			memmove( m_vecEventData.data(), pKeep, m_cubEvents - cubDropped );
		m_cEvents -= iEvent;
		m_cubEvents -= cubDropped;

		uint32_t cubFree = static_cast<uint32_t>( m_vecEventData.size() ) - m_cubEvents;
		if ( cubFree < 1024 )
		{
			GrowEventData( &m_vecEventData, 4096, 1024 - cubFree );
			cubFree = static_cast<uint32_t>( m_vecEventData.size() ) - m_cubEvents;
		}

		const EventHeader_t *pEvent = reinterpret_cast<const EventHeader_t *>( m_vecEventData.data() + m_cubEvents );
		cubRead = cubFree;
		int cNewEvents = ETWWin32::NReadAvailableEvents( const_cast<EventHeader_t *>( pEvent ), &cubRead );
		m_cubEvents += cubRead;
		m_cEvents += cNewEvents;

		for ( ; cNewEvents != 0; --cNewEvents, pEvent = NextEvent( pEvent ) )
		{
			while ( !m_vecProcessQueue.empty() && m_vecProcessQueue[0]->NCompareEventTime( pEvent->m_ulTimestamp ) > 0 )
			{
				if ( m_vecProcessQueue.size() != 1 )
					m_vecProcessQueue[0] = m_vecProcessQueue.back();
				m_vecProcessQueue.pop_back();
				PercolateDown( 0 );
			}

			for ( CMonitoredProcess *pProcess : m_vecProcessQueue )
				pProcess->AddNewEvent( pEvent );

			if ( pEvent->m_eType == EEventType::ProcessStart )
			{
				const auto *pStart = reinterpret_cast<const ProcessStartEvent_t *>( pEvent );
				const auto itSelf = m_mapMonitoredProcesses.find( pStart->m_unPid );
				if ( itSelf != m_mapMonitoredProcesses.end() )
					itSelf->second->AddNewEvent( pEvent );

				const auto itParent = m_mapMonitoredProcesses.find( pStart->m_unParentPid );
				if ( itParent != m_mapMonitoredProcesses.end() )
					itParent->second->AddNewEvent( pEvent );
			}
			else if ( pEvent->m_eType == EEventType::ProcessExit )
			{
				const auto *pExit = reinterpret_cast<const VacProcessMonitor::ProcessExitEvent_t *>( pEvent );
				const auto itSelf = m_mapMonitoredProcesses.find( pExit->m_unPid );
				if ( itSelf != m_mapMonitoredProcesses.end() )
					itSelf->second->AddNewEvent( pEvent );
			}
		}
	} while ( cubRead != 0 );

	m_bInCallback = false;
	for ( size_t iOperation = 0; iOperation < m_vecDeferredOperations.size(); ++iOperation )
	{
		const DeferredOperation_t operation = m_vecDeferredOperations[iOperation];
		if ( operation.m_bRegister )
			RegisterProcess( operation.m_unPid );
		else
			UnregisterProcess( operation.m_unPid );
	}
	m_vecDeferredOperations.clear();

	Schedule( 1000000 );
	LeaveCriticalSection( &m_CritSec );
}

// @note / sapdragon: pids that died stay in the map on purpose, it's what makes BGetCachedProcessData work for a process
// that's gone. the whole map only clears when the last monitored process unregisters
// @orig: 55 8B EC B8 ? ? ? ? E8 ? ? ? ? 53 56 57 8D 45
void CClientProcessMonitor::RebuildProcessNameMap()
{
	DWORD rgunPids[1024];
	uint32_t cubPids;
	ETWWin32::BEnumProcessIds( sizeof( rgunPids ), rgunPids, &cubPids );
	const int cPids = cubPids >> 2;

	auto it = m_mapActiveProcessIdToImagePath.begin();
	const auto itEnd = m_mapActiveProcessIdToImagePath.end();
	int iPid = 0;
	while ( iPid < cPids || it != itEnd )
	{
		bool bInsert = iPid < cPids && ( it == itEnd || it->first > rgunPids[iPid] );
		const bool bStale = iPid >= cPids || ( it != itEnd && it->first < rgunPids[iPid] );
		bool bAdvance = bStale;
		bool bErase = false;
		if ( !bInsert && !bStale )
		{
			uint64_t ulCreationTime;
			if ( !ETWWin32::BGetCreationTimeForPid( rgunPids[iPid], reinterpret_cast<FILETIME *>( &ulCreationTime ) ) )
			{
				++iPid;
				bAdvance = true;
			}
			else if ( it->second.m_ulCreationTime != ulCreationTime )
			{
				bInsert = true;
				bAdvance = true;
				bErase = true;
			}
			else
			{
				++it;
				++iPid;
			}
		}

		if ( bAdvance )
		{
			const auto itCurrent = it;
			++it;
			if ( bErase )
			{
				if ( itCurrent->second.m_pwszImagePath )
					delete[] itCurrent->second.m_pwszImagePath;
				m_mapActiveProcessIdToImagePath.erase( itCurrent );
			}
		}

		if ( bInsert )
		{
			const DWORD unPid = rgunPids[iPid];
			uint64_t ulCreationTime;
			wchar_t wszPath[1024];
			uint32_t cchPath = ARRAYSIZE( wszPath );
			if ( ETWWin32::BGetCreationTimeForPid( unPid, reinterpret_cast<FILETIME *>( &ulCreationTime ) ) &&
			     ETWWin32::BGetImagePathForPid( unPid, wszPath, &cchPath ) )
			{
				wchar_t *pwszPath = new wchar_t[cchPath];
				memcpy( pwszPath, wszPath, 2 * cchPath );
				m_mapActiveProcessIdToImagePath.insert_or_assign( unPid,
				                                                  ActiveProcessData_t{ ulCreationTime, pwszPath } );
			}
			++iPid;
		}
	}
}

// @orig: 55 8B EC 51 53 56 57 8B F9 8D B7 ? ? ? ? 56 FF 15 ? ? ? ? 80 7F
void CClientProcessMonitor::RegisterProcess( uint32_t unPid )
{
	EnterCriticalSection( &m_CritSec );
	if ( m_bInCallback )
	{
		AddDeferredOperation( unPid, true );
		LeaveCriticalSection( &m_CritSec );
		return;
	}

	const auto it = m_mapMonitoredProcesses.find( unPid );
	if ( it != m_mapMonitoredProcesses.end() )
	{
		++it->second->m_cRefs;
		LeaveCriticalSection( &m_CritSec );
		return;
	}

	CMonitoredProcess *pProcess = new CMonitoredProcess( this, unPid );
	if ( !pProcess->m_bHaveCreationTime )
	{
		pProcess->Release();
		delete pProcess;
		LeaveCriticalSection( &m_CritSec );
		return;
	}

	m_mapMonitoredProcesses[unPid] = pProcess;
	m_vecProcessQueue.push_back( pProcess );
	PercolateUp( static_cast<int>( m_vecProcessQueue.size() ) - 1 );

	const EventHeader_t *pEvent = reinterpret_cast<const EventHeader_t *>( m_vecEventData.data() );
	for ( uint32_t iEvent = 0; iEvent < m_cEvents; ++iEvent )
	{
		const EventHeader_t *pNext = NextEvent( pEvent );
		const int nCompare = pProcess->NCompareEventTime( pEvent->m_ulTimestamp );
		if ( nCompare > 0 )
			break;
		if ( nCompare >= 0 )
			pProcess->AddNewEvent( pEvent );
		pEvent = pNext;
	}

	RebuildProcessNameMap();
	LeaveCriticalSection( &m_CritSec );
}

// @orig: 7ebac2a4:0x1005A630 (no unique signature)
bool CClientProcessMonitor::ResumeProcess( uint32_t unPid )
{
	return ResumeProcessById( unPid );
}

// @orig: 7ebac2a4:0x1005A6B0 (no unique signature)
void CClientProcessMonitor::Shutdown()
{
	ETWWin32::StopETW();
}

// @note / sapdragon: this "suspend" is attaching as a debugger and never pumping debug events, so it only holds while
// the calling thread lives and resume has to come from that same thread
// @orig: 7ebac2a4:0x1005A6C0 (no unique signature)
bool CClientProcessMonitor::SuspendProcess( uint32_t unPid )
{
	return SuspendProcessById( unPid );
}

// @orig: 55 8B EC 6A ? FF 75 ? E8 ? ? ? ? 83 C4
bool CClientProcessMonitor::TerminateProcess( uint32_t unPid )
{
	return TerminateProcessById( unPid, 0 );
}

// @orig: 55 8B EC 83 EC ? 53 8B D9 56 8D B3
void CClientProcessMonitor::UnregisterProcess( uint32_t unPid )
{
	EnterCriticalSection( &m_CritSec );
	if ( m_bInCallback )
	{
		AddDeferredOperation( unPid, false );
		LeaveCriticalSection( &m_CritSec );
		return;
	}

	const auto it = m_mapMonitoredProcesses.find( unPid );
	if ( it != m_mapMonitoredProcesses.end() )
	{
		CMonitoredProcess *pProcess = it->second;
		if ( pProcess->Release() == 0 )
		{
			m_mapMonitoredProcesses.erase( it );
			if ( pProcess->NCompareEventTime( CurrentEventTime() ) >= 0 )
			{
				for ( size_t iQueue = 0; iQueue < m_vecProcessQueue.size(); ++iQueue )
				{
					if ( m_vecProcessQueue[iQueue] != pProcess )
						continue;

					if ( iQueue != m_vecProcessQueue.size() - 1 )
						m_vecProcessQueue[iQueue] = m_vecProcessQueue.back();
					m_vecProcessQueue.pop_back();
					const int iElement = PercolateDown( static_cast<int>( iQueue ) );
					if ( iElement == static_cast<int>( iQueue ) )
						PercolateUp( iElement );
					break;
				}
			}

			delete pProcess;

			if ( m_mapMonitoredProcesses.empty() )
			{
				for ( auto &[unActivePid, data] : m_mapActiveProcessIdToImagePath )
				{
					if ( data.m_pwszImagePath )
						delete[] data.m_pwszImagePath;
				}
				m_mapActiveProcessIdToImagePath.clear();
			}
		}
	}
	LeaveCriticalSection( &m_CritSec );
}

} // namespace ClientProcessMonitor
