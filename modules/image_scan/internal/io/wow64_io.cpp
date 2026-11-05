// @binary: 33211402
#include "../scanner.hpp"
#include "bootstrap/bootstrap.hpp"

namespace vac::workers::image_scan
{

namespace
{

constexpr u32 k_cubMappedNameQuery = sizeof( UNICODE_STRING ) + MAX_PATH * sizeof( wchar_t );
static_assert( sizeof( MEMORY_BASIC_INFORMATION ) == 28 && sizeof( MEMORY_BASIC_INFORMATION64 ) == 48 );

} // namespace

// @orig: 55 8B EC 51 56 8B 75
bool IsCrossBitnessProcess( HANDLE hProcess, BOOL *pbCrossBitness ) noexcept
{
	*pbCrossBitness = FALSE;
	if ( g_pImports->IsWow64Process )
	{
		BOOL bSelfWow64 = FALSE;
		BOOL bTargetWow64 = FALSE;
		g_pImports->IsWow64Process( g_pImports->GetCurrentProcess(), &bSelfWow64 );
		if ( bSelfWow64 )
		{
			if ( hProcess == INVALID_HANDLE_VALUE )
			{
				*pbCrossBitness = TRUE;
			}
			else
			{
				g_pImports->IsWow64Process( hProcess, &bTargetWow64 );
				if ( !bTargetWow64 )
					*pbCrossBitness = TRUE;
			}
		}
	}
	return true;
}

// @note / sapdragon: a cross-bitness target with no NtWow64QueryVirtualMemory64 does not fall back to the native query.
// it returns success and leaves the caller's buffer alone, Windows 11 has no such export
// @orig: 55 8B EC 51 51 56 8D 45
NTSTATUS QueryTargetMemory( HANDLE hProcess, u64 ulAddress, EMemoryInfoClass eInfoClass, void *pvBuffer, u64 cubBuffer,
                            u64 *pcubReturned ) noexcept
{
	BOOL bCrossBitness = FALSE;
	if ( IsCrossBitnessProcess( hProcess, &bCrossBitness ) && bCrossBitness )
	{
		if ( g_pImports->NtWow64QueryVirtualMemory64 )
		{
			return g_pImports->NtWow64QueryVirtualMemory64( hProcess, reinterpret_cast<PVOID64>( ulAddress ),
			                                                static_cast<DWORD>( eInfoClass ), pvBuffer, cubBuffer,
			                                                pcubReturned );
		}
	}
	else if ( g_pImports->NtQueryVirtualMemory )
	{
		ULONG cubReturned = 0;
		const NTSTATUS nStatus = g_pImports->NtQueryVirtualMemory(
		    hProcess, reinterpret_cast<void *>( static_cast<uptr>( ulAddress ) ), static_cast<DWORD>( eInfoClass ),
		    pvBuffer, static_cast<ULONG>( cubBuffer ), &cubReturned );
		*pcubReturned = cubReturned;
		return nStatus;
	}
	return 0;
}

// @orig: 55 8B EC 51 51 83 65
NTSTATUS ReadTargetMemory( HANDLE hProcess, u64 ulAddress, void *pvBuffer, u64 cubBuffer, u64 *pcubRead ) noexcept
{
	BOOL bCrossBitness = FALSE;
	if ( IsCrossBitnessProcess( hProcess, &bCrossBitness ) && bCrossBitness )
	{
		if ( g_pImports->NtWow64ReadVirtualMemory64 )
		{
			return g_pImports->NtWow64ReadVirtualMemory64( hProcess, reinterpret_cast<PVOID64>( ulAddress ), pvBuffer,
			                                               cubBuffer, pcubRead );
		}
	}
	else if ( g_pImports->NtReadVirtualMemory )
	{
		ULONG cubRead = 0;
		const NTSTATUS nStatus =
		    g_pImports->NtReadVirtualMemory( hProcess, reinterpret_cast<void *>( static_cast<uptr>( ulAddress ) ),
		                                     pvBuffer, static_cast<ULONG>( cubBuffer ), &cubRead );
		*pcubRead = cubRead;
		return nStatus;
	}
	return 0;
}

// @note / sapdragon: always fills the 64-bit layout, the 32-bit addresses get sign extended
// @orig: 55 8B EC 83 EC ? 56 8D 45
u32 QueryTargetRegion( HANDLE hProcess, u64 ulAddress, MEMORY_BASIC_INFORMATION64 *pInfo ) noexcept
{
	u64 cubReturned = 0;
	BOOL bCrossBitness = FALSE;
	if ( IsCrossBitnessProcess( hProcess, &bCrossBitness ) && bCrossBitness )
	{
		QueryTargetMemory( hProcess, ulAddress, EMemoryInfoClass::MemoryBasicInformation, pInfo, sizeof( *pInfo ),
		                   &cubReturned );
		return static_cast<u32>( cubReturned );
	}

	MEMORY_BASIC_INFORMATION info;
	QueryTargetMemory( hProcess, ulAddress, EMemoryInfoClass::MemoryBasicInformation, &info, sizeof( info ),
	                   &cubReturned );
	if ( cubReturned == sizeof( info ) )
	{
		pInfo->AllocationBase =
		    static_cast<u64>( static_cast<i64>( static_cast<i32>( reinterpret_cast<uptr>( info.AllocationBase ) ) ) );
		pInfo->AllocationProtect = info.AllocationProtect;
		pInfo->BaseAddress =
		    static_cast<u64>( static_cast<i64>( static_cast<i32>( reinterpret_cast<uptr>( info.BaseAddress ) ) ) );
		pInfo->RegionSize = static_cast<u32>( info.RegionSize );
		pInfo->Protect = info.Protect;
		pInfo->State = info.State;
		pInfo->Type = info.Type;
		return sizeof( *pInfo );
	}
	return static_cast<u32>( cubReturned );
}

// @note / sapdragon: when QueryTargetMemory does nothing the length stays 528 and this copies an uninitialized stack
// buffer, so the name is garbage. keep the buffer uninitialized, callers test its first char
// @orig: 55 8B EC 81 EC
u32 QueryTargetMappedName( HANDLE hProcess, u64 ulAddress, wchar_t *pwszName ) noexcept
{
	wchar_t rgwchBuffer[540];
	u64 cubReturned = k_cubMappedNameQuery;
	if ( QueryTargetMemory( hProcess, ulAddress, EMemoryInfoClass::MemoryMappedFilenameInformation, rgwchBuffer,
	                        k_cubMappedNameQuery, &cubReturned ) )
	{
		g_pImports->GetLastError();
		return 0;
	}

	*pwszName = 0;
	if ( !( cubReturned >> 32 ) && static_cast<u32>( cubReturned ) <= sizeof( UNICODE_STRING ) )
		return 0;

	const u32 cChars = static_cast<u32>( cubReturned ) >> 1;
	if ( cChars >= k_cMaxMappedNameChars )
		return 0;

	rgwchBuffer[cChars] = 0;
	CopyWideFill( pwszName, rgwchBuffer + sizeof( UNICODE_STRING ) / sizeof( wchar_t ), k_cMaxMappedNameChars );
	return cChars;
}

} // namespace vac::workers::image_scan
