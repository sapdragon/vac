#pragma once

#include "module_manager/servicemodulemanagerbase.hpp"

#include <condition_variable>
#include <deque>
#include <list>
#include <memory>
#include <mutex>
#include <thread>

class CClientModuleManagerAsync;

class CWorkItemFunctionCall
{
public:
	~CWorkItemFunctionCall();
	bool ThreadProcess();

	CClientModuleManagerAsync *m_pManager = nullptr;
	uint32_t m_uiCRC32 = 0;
	uint32_t m_unFlags = 0;
	uint32_t m_unCallerLow = 0;
	uint32_t m_unCallerHigh = 0;
	int m_nRequest = 0;
	uint32_t m_unFile = 0;
	void *m_pvInput = nullptr;
	uint32_t m_cubInput = 0;
	ECallResult m_eResult = ECallResult::None;
	uint32_t m_cubOutput = 0;
	void *m_pvOutput = nullptr;
};

// @note / sapdragon: stands in for valve's CWorkThreadPool with one thread, the manager only ever adds one
class CWorkThreadPool
{
public:
	~CWorkThreadPool();
	void AddWorkItem( std::unique_ptr<CWorkItemFunctionCall> pItem );
	std::unique_ptr<CWorkItemFunctionCall> GetNextCompletedWorkItem();
	void StartWorkThreads();
	void StopWorkThreads();
	bool BHasPendingWork();
	bool BIsAlive() const { return m_thread.joinable(); }

private:
	void ThreadMain();

	std::mutex m_mutex;
	std::condition_variable m_condition;
	std::deque<std::unique_ptr<CWorkItemFunctionCall>> m_dequePending;
	std::deque<std::unique_ptr<CWorkItemFunctionCall>> m_dequeCompleted;
	std::thread m_thread;
	bool m_bStop = false;
	bool m_bBusy = false;
};

class CClientModuleManagerAsync : public CClientModuleManagerBase
{
public:
	friend class CWorkItemFunctionCall;

	~CClientModuleManagerAsync() override;
	ECallResult CallFunctionAsync( uint32_t uiCRC32, uint32_t unFlags, uint32_t unCallerLow, uint32_t unCallerHigh,
	                               int nRequest, uint32_t unFile, const void *pvInput, uint32_t cubInput,
	                               uint32_t cubOutput );
	ECallResult PollResponseAsync( void *pvBuffer, uint32_t cubBuffer, uint32_t *pcubStatus, uint32_t unFile,
	                               uint32_t unCallerLow );
	void Shutdown();

private:
	CWorkThreadPool m_threadPool;
	std::list<std::unique_ptr<CWorkItemFunctionCall>> m_listCompleted;
};
