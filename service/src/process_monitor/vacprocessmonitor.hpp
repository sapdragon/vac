#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>

namespace VacProcessMonitor
{

enum class EEventType : uint32_t
{
	ProcessStart = 1,
	ProcessExit = 2,
};

#pragma pack( push, 4 )

struct EventHeader_t
{
	uint32_t m_cubEvent;
	uint32_t m_unSequence;
	// @note / sapdragon: always 1 and nothing here reads it, the name is a guess
	uint32_t m_unVersion;
	EEventType m_eType;
	uint64_t m_ulTimestamp;
};
static_assert( sizeof( EventHeader_t ) == 24 );
static_assert( offsetof( EventHeader_t, m_cubEvent ) == 0 );
static_assert( offsetof( EventHeader_t, m_unSequence ) == 4 );
static_assert( offsetof( EventHeader_t, m_unVersion ) == 8 );
static_assert( offsetof( EventHeader_t, m_eType ) == 12 );
static_assert( offsetof( EventHeader_t, m_ulTimestamp ) == 16 );

// @note / sapdragon: on the wire this stops after the terminator, m_cubEvent is 46 plus two per character
struct ProcessStartEvent_t
{
	EventHeader_t m_Header;
	uint32_t m_unPid;
	uint32_t m_unParentPid;
	uint32_t m_unSessionId;
	uint64_t m_ulCreationTime;
	wchar_t m_wszImagePath[1025];
};
static_assert( offsetof( ProcessStartEvent_t, m_unPid ) == 24 );
static_assert( offsetof( ProcessStartEvent_t, m_unParentPid ) == 28 );
static_assert( offsetof( ProcessStartEvent_t, m_unSessionId ) == 32 );
static_assert( offsetof( ProcessStartEvent_t, m_ulCreationTime ) == 36 );
static_assert( offsetof( ProcessStartEvent_t, m_wszImagePath ) == 44 );

struct ProcessExitEvent_t
{
	EventHeader_t m_Header;
	uint32_t m_unPid;
	uint32_t m_unExitCode;
	uint64_t m_ulCreationTime;
	uint64_t m_ulExitTime;
};
static_assert( sizeof( ProcessExitEvent_t ) == 48 );
static_assert( offsetof( ProcessExitEvent_t, m_unPid ) == 24 );
static_assert( offsetof( ProcessExitEvent_t, m_unExitCode ) == 28 );
static_assert( offsetof( ProcessExitEvent_t, m_ulCreationTime ) == 32 );
static_assert( offsetof( ProcessExitEvent_t, m_ulExitTime ) == 40 );

#pragma pack( pop )

struct ActiveProcessData_t
{
	uint64_t m_ulCreationTime;
	wchar_t *m_pwszImagePath;
};
static_assert( sizeof( ActiveProcessData_t ) == 16 );
static_assert( offsetof( ActiveProcessData_t, m_pwszImagePath ) == 8 );

struct IProvider
{
	virtual int NGetProcessCount() = 0;
	virtual uint32_t NGetProcessIds( uint32_t *prgunPids, uint32_t cPids ) = 0;
	virtual bool BGetCachedProcessData( uint32_t unPid, const ActiveProcessData_t **ppData ) = 0;
	virtual int NGetProcessEventMemorySize( uint32_t unPid ) = 0;
	virtual int NGetProcessEventCount( uint32_t unPid ) = 0;
	virtual uint32_t NGetNewEvents( uint32_t unPid, const EventHeader_t *const **pprgpEvents, int nStartEvent,
	                                void *pvBuffer, uint32_t cubBuffer ) = 0;
};

struct ProviderMapping_t
{
	uint32_t m_unVersion;
	IProvider *m_pProvider;
};
static_assert( sizeof( ProviderMapping_t ) == 8 );

class CProvider : public IProvider
{
protected:
	CProvider();

	HANDLE m_hFileMapping;
	ProviderMapping_t *m_pProviderInMap;
};

} // namespace VacProcessMonitor
