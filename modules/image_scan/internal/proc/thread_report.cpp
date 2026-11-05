// @binary: 33211402
#include "thread_report.hpp"
#include "../scanner.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/scan_status.hpp"
#include "crt/intrinsics.hpp"

namespace vac::workers::image_scan
{

// @orig: 55 8B EC 83 E4 ? B8 ? ? ? ? E8 ? ? ? ? 8B 45 ? 56
int RunThreadReport( const Input_t &input, ThreadReport_t &report, u32 *pcubOutput ) noexcept
{
	if ( *pcubOutput < k_cubReport )
		return 4;

	*pcubOutput = k_cubReport;
	memset( &report, 0, k_cubReport );
	memset( &report, 0, k_cubReport );

	if ( !bootstrap::BootstrapMain( &input ) )
	{
		report.m_eStatus = EScanStatus::BootstrapFailed;
		return 0;
	}

	report.m_unMagic = k_unThreadReportMagic;
	report.m_unReserved = 0;
	report.m_unPid = input.m_unPid;

	ProcessProbe_t probe;
	InitProbe( &probe );

	EProbeFlags ePermuted;
	const EProbeFlags eFlags = *PermuteScanAccessFlags( &ePermuted, EScanAccess::Threads );
	const EScanStatus eStatus = ToolhelpSnapshot( &probe, input.m_unPid, eFlags );

	report.m_unLastError = probe.m_unLastError;
	report.m_eFlags = probe.m_eFlags;
	report.m_cModules = static_cast<u32>( probe.m_cModules );

	wchar_t wszMappedName[k_cMaxMappedNameChars];
	wszMappedName[0] = 0;
	report.m_eStatus = eStatus;

	if ( probe.m_cThreads > static_cast<i32>( ARRAYSIZE( report.m_rgRecords ) ) )
		probe.m_cThreads = ARRAYSIZE( report.m_rgRecords );

	if ( eStatus == EScanStatus::Ok )
	{
		for ( i32 iThread = 0; iThread < probe.m_cThreads; ++iThread )
		{
			ThreadRecord_t &record = report.m_rgRecords[iThread];
			record.m_unThreadId = probe.m_pThreads[iThread].m_Entry.th32ThreadID;

			// @note / sapdragon: sign extended on purpose, the query only ever returned the low half
			const u64 ulStart =
			    static_cast<u64>( static_cast<i64>( static_cast<i32>( probe.m_pThreads[iThread].m_unStartAddress ) ) );
			record.m_ulStartAddress = ulStart;

			const ProbeModule_t *pModule = FindModuleByAddress( &probe, ulStart );

			MEMORY_BASIC_INFORMATION64 region;
			region.Protect = 0;
			region.AllocationBase = 0;
			QueryTargetRegion( probe.m_hProcess, ulStart, &region );

			wszMappedName[0] = 0;
			QueryTargetMappedName( probe.m_hProcess, record.m_ulStartAddress, wszMappedName );

			EThreadMemoryFlags eMemoryFlags = static_cast<EThreadMemoryFlags>(
			    static_cast<u32>( region.AllocationBase ) | ( region.Protect & 0xFFF ) );
			if ( wszMappedName[0] )
				eMemoryFlags |= EThreadMemoryFlags::MappedName;
			if ( pModule )
				eMemoryFlags |= EThreadMemoryFlags::InModule;

			record.m_eMemoryFlags = eMemoryFlags;
			++report.m_cRecords;
		}
	}

	CleanupProbe( &probe );
	*pcubOutput = ( sizeof( ThreadRecord_t ) * report.m_cRecords + offsetof( ThreadReport_t, m_rgRecords ) + 7 ) & ~7u;
	bootstrap::BootstrapTeardown();
	return 0;
}

} // namespace vac::workers::image_scan
