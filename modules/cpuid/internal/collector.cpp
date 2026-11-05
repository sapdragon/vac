// @binary: f418b1dc
#include "internal/types.hpp"
#include <intrin.h>

namespace vac::workers::cpuid
{

namespace
{

constexpr u32 k_unEflagsId = 0x200000;

constinit bool s_bCpuidSupported = false;

// @note / sapdragon: the hypervisor range goes before the extended one, the order is part of the report
constexpr u32 k_rgunBaseLeaves[] = { 0x00000000, 0x40000000, 0x80000000 };

constexpr LeafRule_t k_rgLeafRules[] = {
    { 0x00000004, ContinueCacheSubleaf },
    { 0x00000007, ContinueSubleafBelowFirstEax },
    { 0x0000000B, ContinueEaxOrEbx },
    { 0x0000000D, ContinueXsave },
    { 0x0000000F, ContinueRdtMonitoring },
    { 0x00000010, ContinueRdtAllocation },
    { 0x00000014, ContinueSubleafBelowFirstEax },
    { 0x00000017, ContinueSubleafBelowFirstEax },
    { 0x00000018, ContinueSubleafBelowFirstEax },
    { 0x8000001D, ContinueCacheSubleaf },
};

} // namespace

// @orig: 55 8B EC 83 EC ? 83 3D
int Cpuid( u32 *punEax, u32 *punEbx, u32 *punEcx, u32 *punEdx ) noexcept
{
	if ( !s_bCpuidSupported )
	{
		const unsigned long ulFlagsSaved = __readeflags();
		const unsigned long ulFlagsBefore = __readeflags();
		__writeeflags( ulFlagsBefore ^ k_unEflagsId );
		const unsigned long ulFlagsAfter = __readeflags();
		__writeeflags( ulFlagsSaved );
		if ( ( ( ulFlagsBefore ^ ulFlagsAfter ) & k_unEflagsId ) == 0 )
			return 0;
		s_bCpuidSupported = true;
	}

	int rgnRegisters[4];
	__cpuidex( rgnRegisters, static_cast<int>( *punEax ), static_cast<int>( *punEcx ) );
	*punEax = static_cast<u32>( rgnRegisters[0] );
	*punEcx = static_cast<u32>( rgnRegisters[2] );
	*punEbx = static_cast<u32>( rgnRegisters[1] );
	*punEdx = static_cast<u32>( rgnRegisters[3] );
	return 1;
}

// @orig: 8B 44 24 ? 6A ? F6 40
BOOL __cdecl ContinueCacheSubleaf( const CpuidRecord_t *pFirst, const CpuidRecord_t *pCurrent ) noexcept
{
	return ( pCurrent->m_unEax & 0xF ) != 0;
}

// @orig: 8B 44 24 ? 8B 48
BOOL __cdecl ContinueSubleafBelowFirstEax( const CpuidRecord_t *pFirst, const CpuidRecord_t *pCurrent ) noexcept
{
	return pCurrent->m_unSubleaf < pFirst->m_unEax;
}

// @orig: 8B 44 24 ? 83 78 ? ? 75 ? 83 78
BOOL __cdecl ContinueEaxOrEbx( const CpuidRecord_t *pFirst, const CpuidRecord_t *pCurrent ) noexcept
{
	return pCurrent->m_unEax != 0 || pCurrent->m_unEbx != 0;
}

// @orig: 8B 44 24 ? 33 C9 83 78
BOOL __cdecl ContinueXsave( const CpuidRecord_t *pFirst, const CpuidRecord_t *pCurrent ) noexcept
{
	return ( pCurrent->m_unSubleaf <= 1 || pCurrent->m_unEax != 0 || pCurrent->m_unEbx != 0 || pCurrent->m_unEcx != 0 ||
	         pCurrent->m_unEdx != 0 ) &&
	       ( pCurrent->m_unSubleaf != 0 || pCurrent->m_unEax != 0 );
}

// @orig: f418b1dc:0x10002C90 (no unique signature)
BOOL __cdecl ContinueRdtMonitoring( const CpuidRecord_t *pFirst, const CpuidRecord_t *pCurrent ) noexcept
{
	return pCurrent->m_unSubleaf == 0 && ( pCurrent->m_unEdx & 6 ) != 0;
}

// @orig: f418b1dc:0x10002CA7 (no unique signature)
BOOL __cdecl ContinueRdtAllocation( const CpuidRecord_t *pFirst, const CpuidRecord_t *pCurrent ) noexcept
{
	return pCurrent->m_unSubleaf == 0 && ( pCurrent->m_unEbx & 6 ) != 0;
}

// @orig: 83 EC ? 53 55 8B 6C 24
EAppendResult AppendLeaf( Report_t &report, u32 *pcRecords, u32 *punMaxLeaf, u32 unLeaf,
                          PfnContinue_t pfnContinue ) noexcept
{
	const CpuidRecord_t *pFirst = &report.m_rgRecords[*pcRecords];
	u32 unSubleaf = 0;
	for ( ;; )
	{
		CpuidRecord_t *pRecord = &report.m_rgRecords[*pcRecords];
		if ( *pcRecords >= k_cMaxRecords )
			return EAppendResult::RecordsFull;

		pRecord->m_unLeaf = unLeaf;
		pRecord->m_unEax = unLeaf;
		pRecord->m_unSubleaf = unSubleaf;
		pRecord->m_unEcx = unSubleaf;
		++unSubleaf;
		if ( Cpuid( &pRecord->m_unEax, &pRecord->m_unEbx, &pRecord->m_unEcx, &pRecord->m_unEdx ) == 0 )
			return EAppendResult::CpuidUnsupported;

		if ( static_cast<u16>( unLeaf ) == 0 )
			*punMaxLeaf = pRecord->m_unEax;
		++*pcRecords;

		if ( pfnContinue == nullptr || !pfnContinue( pFirst, pRecord ) )
			return EAppendResult::Appended;
	}
}

// @orig: 51 51 53 55 56 33 F6
EScanStatus Collect( Report_t &report ) noexcept
{
	EScanStatus eStatus = EScanStatus::Ok;
	u32 cRecords = 0;
	u32 unMaxLeaf;

	for ( const u32 unBaseLeaf : k_rgunBaseLeaves )
	{
		u32 unLeaf = unBaseLeaf;
		unMaxLeaf = unLeaf;
		do
		{
			PfnContinue_t pfnContinue = nullptr;
			for ( const LeafRule_t &rule : k_rgLeafRules )
			{
				if ( unLeaf < rule.m_unLeaf )
					break;
				if ( unLeaf == rule.m_unLeaf )
					pfnContinue = rule.m_pfnContinue;
			}

			const EAppendResult eAppended = AppendLeaf( report, &cRecords, &unMaxLeaf, unLeaf, pfnContinue );
			if ( eAppended != EAppendResult::Appended )
			{
				if ( eAppended == EAppendResult::RecordsFull )
					eStatus = EScanStatus::RecordOverflow;
				else if ( eAppended == EAppendResult::CpuidUnsupported )
					eStatus = EScanStatus::CpuidUnsupported;
				else
					eStatus = EScanStatus::InternalError;
				report.m_cRecords = cRecords;
				return eStatus;
			}
			++unLeaf;
		} while ( unLeaf <= unMaxLeaf );
	}

	report.m_cRecords = cRecords;
	return eStatus;
}

} // namespace vac::workers::cpuid
