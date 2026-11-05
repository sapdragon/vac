// @binary: 7ebac2a4
#include "module_manager/servicemodulemanagerasync.hpp"

#include <cstdlib>
#include <cstring>

namespace
{

constexpr uint64_t k_ulIdleUnloadSeconds = 1800;

} // namespace

// @orig: 55 8B EC 56 8B F1 83 BE
CWorkItemFunctionCall::~CWorkItemFunctionCall()
{
	free( m_pvInput );
	free( m_pvOutput );
}

// @orig: 56 8B F1 8B 86 ? ? ? ? 8D 8E
bool CWorkItemFunctionCall::ThreadProcess()
{
	if ( m_unFlags & MF_LEGACY_COMPATIBLE )
		m_eResult = m_pManager->CallFunctionAsyncInternal_LegacyCompat(
		    m_uiCRC32, m_unFlags, m_nRequest, m_unFile, m_pvInput, m_cubInput, &m_pvOutput, &m_cubOutput );
	else
		m_eResult = m_pManager->CallFunctionAsyncInternal( m_uiCRC32, m_unFlags, m_nRequest, m_pvInput, m_cubInput,
		                                                   &m_pvOutput, &m_cubOutput );

	free( m_pvInput );
	m_pvInput = nullptr;
	return true;
}

CWorkThreadPool::~CWorkThreadPool()
{
	StopWorkThreads();
}

void CWorkThreadPool::ThreadMain()
{
	for ( ;; )
	{
		std::unique_ptr<CWorkItemFunctionCall> pItem;
		{
			std::unique_lock lock( m_mutex );
			m_condition.wait( lock, [this] { return m_bStop || !m_dequePending.empty(); } );
			if ( m_bStop )
				return;
			pItem = std::move( m_dequePending.front() );
			m_dequePending.pop_front();
			m_bBusy = true;
		}

		pItem->ThreadProcess();

		std::lock_guard lock( m_mutex );
		m_dequeCompleted.push_back( std::move( pItem ) );
		m_bBusy = false;
	}
}

void CWorkThreadPool::AddWorkItem( std::unique_ptr<CWorkItemFunctionCall> pItem )
{
	{
		std::lock_guard lock( m_mutex );
		m_dequePending.push_back( std::move( pItem ) );
	}
	m_condition.notify_one();
}

std::unique_ptr<CWorkItemFunctionCall> CWorkThreadPool::GetNextCompletedWorkItem()
{
	std::lock_guard lock( m_mutex );
	if ( m_dequeCompleted.empty() )
		return nullptr;
	auto pItem = std::move( m_dequeCompleted.front() );
	m_dequeCompleted.pop_front();
	return pItem;
}

void CWorkThreadPool::StartWorkThreads()
{
	m_thread = std::thread( &CWorkThreadPool::ThreadMain, this );
}

void CWorkThreadPool::StopWorkThreads()
{
	if ( !m_thread.joinable() )
		return;
	{
		std::lock_guard lock( m_mutex );
		m_bStop = true;
	}
	m_condition.notify_all();
	m_thread.join();
}

bool CWorkThreadPool::BHasPendingWork()
{
	std::lock_guard lock( m_mutex );
	return m_bBusy || !m_dequePending.empty();
}

// @orig: 7ebac2a4:0x10056720 (no unique signature)
CClientModuleManagerAsync::~CClientModuleManagerAsync()
{
	Shutdown();
}

// @orig: 55 8B EC 53 8B D9 56 8B 8B
ECallResult CClientModuleManagerAsync::CallFunctionAsync( uint32_t uiCRC32, uint32_t unFlags, uint32_t unCallerLow,
                                                          uint32_t unCallerHigh, int nRequest, uint32_t unFile,
                                                          const void *pvInput, uint32_t cubInput, uint32_t cubOutput )
{
	if ( !m_threadPool.BIsAlive() )
		m_threadPool.StartWorkThreads();

	auto pItem = std::make_unique<CWorkItemFunctionCall>();
	pItem->m_uiCRC32 = uiCRC32;
	pItem->m_unFlags = unFlags;
	pItem->m_unCallerLow = unCallerLow;
	pItem->m_unCallerHigh = unCallerHigh;
	pItem->m_nRequest = nRequest;
	pItem->m_unFile = unFile;
	pItem->m_cubInput = cubInput;
	pItem->m_pManager = this;
	pItem->m_cubOutput = cubOutput;
	pItem->m_pvInput = malloc( cubInput );
	memcpy( pItem->m_pvInput, pvInput, cubInput );
	m_threadPool.AddWorkItem( std::move( pItem ) );
	return ECallResult::OK;
}

// @orig: 55 8B EC 51 53 8B D9 56 57 8B B3
ECallResult CClientModuleManagerAsync::PollResponseAsync( void *pvBuffer, uint32_t cubBuffer, uint32_t *pcubStatus,
                                                          uint32_t unFile, uint32_t unCallerLow )
{
	std::unique_ptr<CWorkItemFunctionCall> pItem;
	for ( auto it = m_listCompleted.begin(); it != m_listCompleted.end(); ++it )
	{
		if ( ( *it )->m_unCallerLow == unCallerLow && ( *it )->m_unFile == unFile )
		{
			pItem = std::move( *it );
			m_listCompleted.erase( it );
			break;
		}
	}

	if ( !pItem )
	{
		for ( pItem = m_threadPool.GetNextCompletedWorkItem(); pItem; pItem = m_threadPool.GetNextCompletedWorkItem() )
		{
			if ( pItem->m_unCallerLow == unCallerLow && pItem->m_unFile == unFile )
				break;
			m_listCompleted.push_back( std::move( pItem ) );
		}
	}

	if ( m_listCompleted.empty() && !m_threadPool.BHasPendingWork() )
	{
		const uint64_t ulNow = CurrentMicroSecs();
		for ( auto it = m_mapModules.begin(); it != m_mapModules.end(); )
		{
			const auto itCurrent = it++;
			if ( ( ulNow - itCurrent->second->m_ulLastUsedMicroSecs ) / 1000000 > k_ulIdleUnloadSeconds )
				UnloadModule( itCurrent->first );
		}
	}

	*pcubStatus = 0;
	if ( !pItem )
		return ECallResult::None;

	const ECallResult eResult = pItem->m_eResult;
	*pcubStatus = pItem->m_cubOutput;
	if ( cubBuffer >= pItem->m_cubOutput )
	{
		if ( pItem->m_cubOutput )
			memcpy( pvBuffer, pItem->m_pvOutput, pItem->m_cubOutput );
		return eResult;
	}

	// @note / sapdragon: a crash report that doesn't fit is too large, everything else that doesn't fit is too small.
	// looks backwards but the original branches exactly like this
	return eResult == ECallResult::Exception ? ECallResult::OutputTooLarge : ECallResult::OutputTooSmall;
}

// @orig: 55 8B EC 51 83 B9 ? ? ? ? ? 74
void CClientModuleManagerAsync::Shutdown()
{
	m_threadPool.StopWorkThreads();
	while ( m_threadPool.GetNextCompletedWorkItem() )
	{
	}
}
