#pragma once

#include "process_monitor/vacprocessmonitor.hpp"

#include <cstdint>
#include <map>
#include <unordered_map>
#include <vector>

class IClientProcessMonitor
{
public:
	virtual void RegisterProcess( uint32_t unPid ) = 0;
	virtual void UnregisterProcess( uint32_t unPid ) = 0;
	virtual bool TerminateProcess( uint32_t unPid ) = 0;
	virtual bool SuspendProcess( uint32_t unPid ) = 0;
	virtual bool ResumeProcess( uint32_t unPid ) = 0;
};

namespace ClientProcessMonitor
{

class CClientProcessMonitor;

class CMonitoredProcess
{
public:
	CMonitoredProcess( CClientProcessMonitor *pMonitor, uint32_t unPid );
	virtual ~CMonitoredProcess();
	virtual void OnFinalRelease() {}

	int Release();
	void AddNewEvent( const VacProcessMonitor::EventHeader_t *pEvent );
	int NCompareEventTime( uint64_t ulTime ) const;
	static bool BProcessTimeSortFunc( CMonitoredProcess *const &pLeft, CMonitoredProcess *const &pRight );

	uint32_t m_cRefs;
	CClientProcessMonitor *m_pMonitor;
	bool m_bHaveCreationTime;
	uint32_t m_unPid;
	uint64_t m_ulCreationTime;
	uint32_t m_unLastSequence;
	uint32_t m_cubEvents;
	std::vector<uint8_t> m_vecEventData;
	std::vector<const VacProcessMonitor::EventHeader_t *> m_vecEventHeaders;
	std::vector<uint32_t> m_vecChildPids;
};

class CClientProcessMonitor : public IClientProcessMonitor, public VacProcessMonitor::CProvider
{
public:
	CClientProcessMonitor();

	void RegisterProcess( uint32_t unPid ) override;
	void UnregisterProcess( uint32_t unPid ) override;
	bool TerminateProcess( uint32_t unPid ) override;
	bool SuspendProcess( uint32_t unPid ) override;
	bool ResumeProcess( uint32_t unPid ) override;

	int NGetProcessCount() override;
	uint32_t NGetProcessIds( uint32_t *prgunPids, uint32_t cPids ) override;
	bool BGetCachedProcessData( uint32_t unPid, const VacProcessMonitor::ActiveProcessData_t **ppData ) override;
	int NGetProcessEventMemorySize( uint32_t unPid ) override;
	int NGetProcessEventCount( uint32_t unPid ) override;
	uint32_t NGetNewEvents( uint32_t unPid, const VacProcessMonitor::EventHeader_t *const **pprgpEvents,
	                        int nStartEvent, void *pvBuffer, uint32_t cubBuffer ) override;

	void OnScheduledCallback();
	void Shutdown();

	// @note / sapdragon: stand only. valve's scheduler is a frame loop that lives elsewhere, here we only remember when
	// the next run is due and whoever hosts this calls OnScheduledCallback
	uint64_t GetNextCallbackMicroSecs() const { return m_ulNextCallbackMicroSecs; }

protected:
	struct DeferredOperation_t
	{
		bool m_bRegister;
		uint32_t m_unPid;
	};
	static_assert( sizeof( DeferredOperation_t ) == 8 );

	void AddDeferredOperation( uint32_t unPid, bool bRegister );
	void RebuildProcessNameMap();
	int PercolateUp( int iElement );
	int PercolateDown( int iElement );
	void Schedule( uint32_t unMicroSecs );

	uint32_t m_cEvents;
	uint32_t m_cubEvents;
	std::vector<uint8_t> m_vecEventData;
	bool m_bInCallback;
	std::vector<DeferredOperation_t> m_vecDeferredOperations;
	std::vector<CMonitoredProcess *> m_vecProcessQueue;
	std::unordered_map<uint32_t, CMonitoredProcess *> m_mapMonitoredProcesses;
	std::map<uint32_t, VacProcessMonitor::ActiveProcessData_t> m_mapActiveProcessIdToImagePath;
	uint64_t m_ulNextCallbackMicroSecs;
	CRITICAL_SECTION m_CritSec;
};

} // namespace ClientProcessMonitor
