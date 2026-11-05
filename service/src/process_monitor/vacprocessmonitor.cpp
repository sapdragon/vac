// @binary: 7ebac2a4
#include "process_monitor/vacprocessmonitor.hpp"

namespace VacProcessMonitor
{

// @orig: 55 8B EC 83 EC ? 56 8B F1 C7 06
CProvider::CProvider()
{
	m_hFileMapping = INVALID_HANDLE_VALUE;
	m_pProviderInMap = nullptr;

	char szName[60];
	wsprintfA( szName, "Steam_{E9FD3C51-9B58-4DA0-962C-734882B19273}_Pid:%000008X", GetCurrentProcessId() );
	m_hFileMapping =
	    CreateFileMappingA( INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof( ProviderMapping_t ), szName );

	if ( m_hFileMapping )
		m_pProviderInMap = static_cast<ProviderMapping_t *>( MapViewOfFile( m_hFileMapping, FILE_MAP_WRITE, 0, 0, 0 ) );

	if ( m_pProviderInMap )
	{
		m_pProviderInMap->m_unVersion = 196612;
		m_pProviderInMap->m_pProvider = this;
	}
}

} // namespace VacProcessMonitor
