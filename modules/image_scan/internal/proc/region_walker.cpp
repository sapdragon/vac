// @binary: 33211402
#include "../scanner.hpp"
#include "bootstrap/bootstrap.hpp"

namespace vac::workers::image_scan
{

// @orig: 55 8B EC 83 E4 ? 83 EC
bool WalkProcessRegion( HANDLE hProcess, RegionWalk_t *pWalk ) noexcept
{
	bool bReservedGap = false;

	pWalk->m_ulFirstCommitted = 0;
	pWalk->m_ulCommittedEnd = 0;
	pWalk->m_ulContiguousEnd = 0;
	pWalk->m_cubTotal = 0;
	pWalk->m_unProtectMask = 0;
	pWalk->m_unExecutableProtectMask = 0;
	pWalk->m_cRegions = 0;
	pWalk->m_cCommitted = 0;
	pWalk->m_cubContiguous = 0;

	if ( pWalk->m_ulCursor && pWalk->m_ulNext <= pWalk->m_ulCursor )
		return false;

	pWalk->m_ulCursor = pWalk->m_ulNext;
	pWalk->m_ulCurrent = pWalk->m_ulNext;
	if ( QueryTargetRegion( hProcess, pWalk->m_ulNext, &pWalk->m_First ) != sizeof( pWalk->m_First ) )
	{
		pWalk->m_unLastError = g_pImports->GetLastError();
		return false;
	}
	if ( pWalk->m_First.RegionSize == MAXDWORD )
		return false;

	u64 ulAddress = pWalk->m_ulNext;
	pWalk->m_ulCurrent = ulAddress;

	MEMORY_BASIC_INFORMATION64 info;
	u32 cubInfo = QueryTargetRegion( hProcess, ulAddress, &info );
	pWalk->m_ulNext = ulAddress;
	for ( ;; )
	{
		if ( cubInfo != sizeof( info ) )
		{
			pWalk->m_unLastError = g_pImports->GetLastError();
			return true;
		}
		if ( info.AllocationBase != pWalk->m_First.AllocationBase )
			return true;

		const u64 ulEnd = ulAddress + info.RegionSize;
		if ( info.State == MEM_FREE )
		{
			pWalk->m_cubTotal += info.RegionSize;
			pWalk->m_ulNext = ulEnd;
			pWalk->m_unProtectMask |= info.Protect;
			++pWalk->m_cRegions;
			return true;
		}

		if ( info.State == MEM_RESERVE )
		{
			if ( pWalk->m_ulFirstCommitted )
			{
				pWalk->m_cubTotal += info.RegionSize;
				bReservedGap = true;
			}
			++pWalk->m_cRegions;
		}
		else if ( info.State == MEM_COMMIT )
		{
			pWalk->m_ulCommittedEnd = ulEnd;
			if ( !bReservedGap )
			{
				pWalk->m_cubContiguous += info.RegionSize;
				pWalk->m_ulContiguousEnd = ulEnd;
			}
			if ( !pWalk->m_ulFirstCommitted )
				pWalk->m_ulFirstCommitted = ulAddress;
			pWalk->m_cubTotal += info.RegionSize;
			pWalk->m_unProtectMask |= info.Protect;
			if ( info.Protect & ( PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY ) )
				pWalk->m_unExecutableProtectMask |= info.Protect;
			++pWalk->m_cRegions;
			++pWalk->m_cCommitted;
		}

		if ( ulEnd <= ulAddress )
			return true;

		pWalk->m_ulCurrent = ulEnd;
		ulAddress = ulEnd;
		cubInfo = QueryTargetRegion( hProcess, ulEnd, &info );
		pWalk->m_ulNext = ulEnd;
	}
}

// @note / sapdragon: nothing allocates the scratch in this build, and these free arguments would fail anyway
// @orig: 56 8B F1 83 7E ? ? 74 ? A1 ? ? ? ? 68
void ReleaseScanSession( ScanSession_t *pSession ) noexcept
{
	if ( pSession->m_pvScratch )
	{
		g_pImports->VirtualFree( pSession->m_pvScratch, 0x400000, MEM_FREE );
		pSession->m_pvScratch = nullptr;
	}
}

} // namespace vac::workers::image_scan
