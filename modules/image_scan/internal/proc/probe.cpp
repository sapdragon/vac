// @binary: 33211402
#include "../scanner.hpp"
#include "bootstrap/bootstrap.hpp"
#include "crt/intrinsics.hpp"
#include "process/process.hpp"

namespace vac::workers::image_scan
{

namespace
{

// @orig: 55 8B EC 51 A1
bool QueryThreadStartAddress( HANDLE hThread, u32 *punStartAddress ) noexcept
{
	u32 unStartAddress;
	if ( g_pImports->NtQueryInformationThread( hThread, static_cast<THREADINFOCLASS>( 9 ), &unStartAddress,
	                                           sizeof( unStartAddress ), nullptr ) < 0 )
		return false;
	*punStartAddress = unStartAddress;
	return true;
}

} // namespace

// @orig: 53 55 56 57 8B F9 33 F6 39 B7
ProbeModule_t *FindModuleByPath( const ProcessProbe_t *pProbe, const wchar_t *pwszPath ) noexcept
{
	for ( i32 iModule = 0; iModule < pProbe->m_cModules; ++iModule )
	{
		ProbeModule_t *pModule = &pProbe->m_pModules[iModule];
		if ( !ComparePathPrefix( pModule->m_wszFullName, pwszPath, 520 ) )
			return pModule;
	}
	return nullptr;
}

// @orig: 53 55 56 8B B1
ProbeModule_t *FindModuleByAddress( const ProcessProbe_t *pProbe, u64 ulAddress ) noexcept
{
	for ( i32 iModule = 0; iModule < pProbe->m_cModules; ++iModule )
	{
		ProbeModule_t *pModule = &pProbe->m_pModules[iModule];
		if ( ulAddress >= pModule->m_ulBase && ulAddress < pModule->m_ulBase + pModule->m_cubImage )
			return pModule;
	}
	return nullptr;
}

// @orig: 56 68 ? ? ? ? 8B F1
void InitProbe( ProcessProbe_t *pProbe ) noexcept
{
	memset( pProbe, 0, sizeof( *pProbe ) );
	pProbe->m_hProcess = INVALID_HANDLE_VALUE;
}

// @orig: 81 EC ? ? ? ? 8A 84 24 ? ? ? ? 53 55 56 8B B4 24 ? ? ? ? 8B D9 57 88 44 24 ? A1
EScanStatus ToolhelpSnapshot( ProcessProbe_t *pProbe, u32 unPid, EProbeFlags eFlags ) noexcept
{
	pProbe->m_hProcess = g_pImports->OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, unPid );
	if ( !pProbe->m_hProcess )
	{
		pProbe->m_unLastError = g_pImports->GetLastError();
		return EScanStatus::ProcessReopenFailed;
	}

	const bool bSnapModules = HasFlag( eFlags, EProbeFlags::Modules );
	const bool bSnapThreads = HasFlag( eFlags, EProbeFlags::Threads );
	if ( !bSnapModules && !bSnapThreads )
		return EScanStatus::Ok;

	DWORD unSnapshotFlags = bSnapThreads ? TH32CS_SNAPTHREAD : 0;
	if ( bSnapModules )
		unSnapshotFlags |= TH32CS_SNAPMODULE;

	const HANDLE hSnapshot =
	    g_pImports->CreateToolhelp32Snapshot( unSnapshotFlags, unSnapshotFlags != TH32CS_SNAPTHREAD ? unPid : 0 );
	if ( hSnapshot == INVALID_HANDLE_VALUE )
	{
		pProbe->m_unLastError = g_pImports->GetLastError();
		return EScanStatus::ProcessReadFailed;
	}

	pProbe->m_cModules = 0;
	pProbe->m_cThreads = 0;
	pProbe->m_unPid = unPid;

	// @note / sapdragon: unreachable, both workers pass flags without this bit. the counts and the target are Valve's:
	// they copy the exe path and then the module name over the same field, past its end
	if ( bSnapModules )
	{
		MODULEENTRY32W entry;
		entry.dwSize = sizeof( entry );
		if ( g_pImports->Module32FirstW( hSnapshot, &entry ) )
		{
			pProbe->m_pModules = static_cast<ProbeModule_t *>( AllocBytes( sizeof( ProbeModule_t ) ) );
			do
			{
				ProbeModule_t module;
				memset( &module, 0, sizeof( module ) );
				module.m_ulBase = static_cast<u64>(
				    static_cast<i64>( static_cast<i32>( reinterpret_cast<uptr>( entry.modBaseAddr ) ) ) );
				module.m_cubImage = entry.modBaseSize;
				CopyWideFill( module.m_wszFullName, entry.szExePath, 520 );
				CopyWideFill( module.m_wszFullName, entry.szModule, 512 );

				pProbe->m_pModules = static_cast<ProbeModule_t *>(
				    ReallocBytes( pProbe->m_pModules, sizeof( ProbeModule_t ) * ( pProbe->m_cModules + 1 ) ) );
				memcpy( &pProbe->m_pModules[pProbe->m_cModules], &module, sizeof( module ) );
				++pProbe->m_cModules;
			} while ( g_pImports->Module32NextW( hSnapshot, &entry ) );
		}
	}

	if ( bSnapThreads )
	{
		THREADENTRY32 entry;
		entry.dwSize = sizeof( entry );
		if ( g_pImports->Thread32First( hSnapshot, &entry ) )
		{
			pProbe->m_cThreads = 0;
			do
			{
				if ( entry.th32OwnerProcessID == pProbe->m_unPid )
					++pProbe->m_cThreads;
			} while ( g_pImports->Thread32Next( hSnapshot, &entry ) );
		}

		if ( pProbe->m_cThreads > 0 )
		{
			pProbe->m_pThreads =
			    static_cast<ProbeThread_t *>( AllocBytes( sizeof( ProbeThread_t ) * pProbe->m_cThreads ) );

			entry.dwSize = sizeof( entry );
			g_pImports->Thread32First( hSnapshot, &entry );
			ProbeThread_t *pThread = pProbe->m_pThreads;
			do
			{
				if ( entry.th32OwnerProcessID == pProbe->m_unPid )
				{
					memcpy( &pThread->m_Entry, &entry, sizeof( entry ) );
					if ( g_pImports->OpenThread && g_pImports->NtQueryInformationThread )
					{
						const HANDLE hThread =
						    g_pImports->OpenThread( THREAD_QUERY_INFORMATION, FALSE, pThread->m_Entry.th32ThreadID );
						if ( hThread )
						{
							QueryThreadStartAddress( hThread, &pThread->m_unStartAddress );
							CloseHandle( hThread );
						}
					}
					++pThread;
				}
				entry.dwSize = sizeof( entry );
			} while ( g_pImports->Thread32Next( hSnapshot, &entry ) );

			const u32 cubStacks = 24 * static_cast<u32>( pProbe->m_cThreads );
			pProbe->m_pThreadStacks = AllocBytes( cubStacks );
			memset( pProbe->m_pThreadStacks, 0, cubStacks );
		}
	}

	g_pImports->CloseHandle( hSnapshot );

	if ( bSnapThreads && !pProbe->m_cThreads )
		return EScanStatus::NoThreads;
	if ( !bSnapModules || pProbe->m_cModules )
		return EScanStatus::Ok;
	return EScanStatus::TooManyModules;
}

// @orig: 56 8B F1 8B 8E
void CleanupProbe( ProcessProbe_t *pProbe ) noexcept
{
	if ( pProbe->m_pModules )
		FreeBytes( pProbe->m_pModules );
	pProbe->m_pModules = nullptr;
	pProbe->m_cModules = 0;

	if ( pProbe->m_pThreads )
		FreeBytes( pProbe->m_pThreads );
	if ( pProbe->m_pThreadStacks )
		FreeBytes( pProbe->m_pThreadStacks );
	if ( pProbe->m_pUnusedTableA )
		FreeBytes( pProbe->m_pUnusedTableA );
	if ( pProbe->m_pUnusedTableB )
		FreeBytes( pProbe->m_pUnusedTableB );

	if ( pProbe->m_hProcess != INVALID_HANDLE_VALUE && pProbe->m_hProcess )
		g_pImports->CloseHandle( pProbe->m_hProcess );

	memset( pProbe, 0, sizeof( *pProbe ) );
	pProbe->m_hProcess = INVALID_HANDLE_VALUE;
}

} // namespace vac::workers::image_scan
