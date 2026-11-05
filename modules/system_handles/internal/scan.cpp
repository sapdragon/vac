// @binary: 1da8fb5c
#include "internal/types.hpp"
#include "bootstrap/bootstrap.hpp"
#include "crt/intrinsics.hpp"
#include "process/process.hpp"
#include "util/encoding.hpp"
#include "util/hashing.hpp"
#include "util/wstr.hpp"
#include "util/xor_string.hpp"

#include <intrin.h>

namespace vac::workers::system_handles
{

namespace
{

constexpr u32 k_unSystemHandleInformation = 16;
constexpr u32 k_unFileTimeTicksPerSecond = 10000000;
constexpr u32 k_cchImagePath = 512;

using PfnNtQuerySystemInformation_t = NTSTATUS( WINAPI * )( u32, void *, ULONG, ULONG * );

#pragma pack( push, 1 )
struct SystemHandleEntry_t
{
	// @note / sapdragon: valve reads the pid as a dword, so the back trace index in the high word comes along
	u32 m_unPidAndBackTrace;
	u8 m_unObjectType;
	u8 m_unFlags;
	u16 m_unHandle;
	u32 m_unObject;
	u32 m_unGrantedAccess;
};

struct SystemHandleInformation_t
{
	int m_cHandles;
	SystemHandleEntry_t m_rgHandles[1];
};
#pragma pack( pop )
VAC_LAYOUT_SIZE( SystemHandleEntry_t, 16 );

// @note / sapdragon: stands in for __aulldiv, there is no crt here. valve keeps only the low dword anyway
u32 FileTimeToSeconds( u64 ulFileTime ) noexcept
{
	const u32 unHigh = static_cast<u32>( ulFileTime >> 32 ) % k_unFileTimeTicksPerSecond;
	const u64 ulRest = ( static_cast<u64>( unHigh ) << 32 ) | static_cast<u32>( ulFileTime );
	unsigned int unRemainder;
	return _udiv64( ulRest, k_unFileTimeTicksPerSecond, &unRemainder );
}

// @orig: FF 74 24 ? 52
int CompareDevicePrefix( const wchar_t *pwszPath, const wchar_t *pwszDevice, int cchDevice ) noexcept
{
	return CompareStringW( LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, pwszPath, cchDevice, pwszDevice, cchDevice ) -
	       CSTR_EQUAL;
}

// @orig: 56 57 8B F2 8B F9
void CopyImagePath( wchar_t *pwszDst, const wchar_t *pwszSrc ) noexcept
{
	memcpy( pwszDst, pwszSrc, k_cchImagePath * sizeof( wchar_t ) );
	const u32 cchSrc = lstrlenW( pwszSrc );
	if ( cchSrc < k_cchImagePath )
		memset( pwszDst + cchSrc, 0, ( k_cchImagePath - cchSrc ) * sizeof( wchar_t ) );
}

// @orig: 81 EC ? ? ? ? 53 55 33 C0
bool DeviceToDosPath( wchar_t *pwszPath ) noexcept
{
	// @note / sapdragon: long paths run from the joined buffer into the device one and the copy reads 1024 bytes
	// from the start, so they stay neighbours like on valve's stack
	struct
	{
		wchar_t m_wszJoined[MAX_PATH];
		wchar_t m_wszDevice[MAX_PATH];
	} buffers;

	wchar_t wszDrives[MAX_PATH];
	wszDrives[0] = 0;
	if ( !g_pImports->GetLogicalDriveStringsW( 250, wszDrives ) )
		return false;

	const wchar_t *pwszDrive = wszDrives;
	wchar_t wszDrive[3] = L"C:";
	wchar_t wchDrive = wszDrives[0];
	for ( ;; )
	{
		wszDrive[0] = wchDrive;
		if ( g_pImports->QueryDosDeviceW( wszDrive, buffers.m_wszDevice, ARRAYSIZE( buffers.m_wszDevice ) ) )
		{
			const u32 cchDevice = lstrlenW( buffers.m_wszDevice );
			if ( cchDevice < ARRAYSIZE( buffers.m_wszDevice ) &&
			     !CompareDevicePrefix( pwszPath, buffers.m_wszDevice, cchDevice ) )
			{
				buffers.m_wszJoined[0] = 0;
				lstrcatW( buffers.m_wszJoined, wszDrive );
				lstrcatW( buffers.m_wszJoined, pwszPath + cchDevice );
				CopyImagePath( pwszPath, buffers.m_wszJoined );
				return true;
			}
		}

		while ( *pwszDrive++ )
			;
		wchDrive = *pwszDrive;
		if ( !wchDrive )
			return false;
	}
}

// @orig: 81 EC ? ? ? ? A1
int EnumerateProcesses( u32 *punPids, u32 *punParentPids ) noexcept
{
	int cProcesses = 0;
	const bool bWalked =
	    process::ForEachSnapshotProcess( g_pImports,
	                                     [&]( const PROCESSENTRY32W &entry )
	                                     {
		                                     if ( cProcesses < k_cMaxPids )
		                                     {
			                                     int iInsert = cProcesses;
			                                     while ( iInsert > 0 && punPids[iInsert - 1] > entry.th32ProcessID )
			                                     {
				                                     punPids[iInsert] = punPids[iInsert - 1];
				                                     punParentPids[iInsert] = punParentPids[iInsert - 1];
				                                     --iInsert;
			                                     }
			                                     ++cProcesses;
			                                     punPids[iInsert] = entry.th32ProcessID;
			                                     punParentPids[iInsert] = entry.th32ParentProcessID;
		                                     }
		                                     return true;
	                                     } );

	// @note / sapdragon: a failed snapshot reports 60 processes, the callers use it as a real count. valve bug, keep it
	return bWalked ? cProcesses : 60;
}

// @orig: 83 EC ? 83 24 24
EScanStatus GetSystemHandles( u32 *punPids, int cPids, int *pcExtraPids, u32 *pcHandles, HandleMask_t *pMasks ) noexcept
{
	auto szQuery = util::MakeXorString<0x5E>( "NtQuerySystemInformation" );
	szQuery.Decode();

	const auto pfnQuery = reinterpret_cast<PfnNtQuerySystemInformation_t>(
	    g_pImports->GetProcAddress( g_pSession->m_hNtdll, szQuery.Get() ) );
	if ( !pfnQuery )
		return static_cast<EScanStatus>( g_pImports->GetLastError() );

	SystemHandleInformation_t *pInformation = nullptr;
	u32 cubBuffer = 0;
	EScanStatus eStatus;
	for ( ;; )
	{
		cubBuffer += 0x100000;
		if ( pInformation )
			g_pImports->VirtualFree( pInformation, 0, MEM_RELEASE );

		pInformation = static_cast<SystemHandleInformation_t *>(
		    g_pImports->VirtualAlloc( nullptr, cubBuffer, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) );
		if ( !pInformation )
			return static_cast<EScanStatus>( g_pImports->GetLastError() );

		eStatus = static_cast<EScanStatus>( pfnQuery( k_unSystemHandleInformation, pInformation, cubBuffer, nullptr ) );
		if ( static_cast<NTSTATUS>( eStatus ) != STATUS_INFO_LENGTH_MISMATCH )
			break;
	}

	if ( eStatus == EScanStatus::Ok )
	{
		*pcHandles = pInformation->m_cHandles;
		*pcExtraPids = 0;

		int iPid = 0;
		for ( int iHandle = 0; iHandle < pInformation->m_cHandles; ++iHandle )
		{
			const SystemHandleEntry_t &entry = pInformation->m_rgHandles[iHandle];
			const u32 unPid = entry.m_unPidAndBackTrace;

			// @note / sapdragon: the search starts where the last one ended, handles of one process come in a row
			bool bFound = false;
			for ( int iTry = 0; iTry < cPids; ++iTry )
			{
				if ( punPids[iPid] == unPid )
				{
					bFound = true;
					break;
				}
				if ( ++iPid >= cPids )
					iPid %= cPids;
			}

			if ( !bFound )
			{
				++*pcExtraPids;
				if ( cPids < k_cMaxPids )
				{
					punPids[cPids] = unPid;
					iPid = cPids++;
				}
			}

			if ( punPids[iPid] == unPid )
			{
				u32 unLow = 0;
				u32 unHigh = 0;
				if ( entry.m_unObjectType < 55 )
				{
					if ( entry.m_unObjectType < 32 )
						unLow = 1u << entry.m_unObjectType;
					else
						unHigh = 1u << ( entry.m_unObjectType - 32 );
				}

				HandleMask_t &mask = pMasks[iPid];
				u32 unMaskHigh = mask.m_unHigh;
				if ( unMaskHigh < 0xFF000000 )
					unMaskHigh += 0x01000000;
				mask.m_unLow |= unLow;
				mask.m_unHigh = unMaskHigh | unHigh;
			}
		}
	}

	g_pImports->VirtualFree( pInformation, 0, MEM_RELEASE );
	return eStatus;
}

// @orig: 81 EC ? ? ? ? 53 55 56
bool CollectProcess( ScanContext_t &context, u32 unPid, u32 unParentPidAndFlags, u32 unMaskLow,
                     u32 unMaskHigh ) noexcept
{
	Report_t &report = *context.m_pReport;
	ProcessRecord_t &record = report.m_rgRecords[report.m_cRecords];

	HANDLE hProcess = g_pImports->OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, unPid );
	if ( ( g_pSession->m_OsVersion.dwPlatformId != VER_PLATFORM_WIN32_NT ||
	       g_pSession->m_OsVersion.dwMajorVersion < 6 ) &&
	     ( !hProcess || hProcess == INVALID_HANDLE_VALUE ) )
	{
		hProcess = g_pImports->OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, unPid );
	}

	u32 unDirectoryHash = 0;
	u32 unBaseNameHash = 0;
	u64 ulCreateTime = 0;
	u32 unCreateSeconds = 0;
	u32 unError = 0;
	u32 unFlags;

	if ( !hProcess || hProcess == INVALID_HANDLE_VALUE )
	{
		unError = g_pImports->GetLastError();
		// @note / sapdragon: the brute forced pids that do not exist end here
		if ( unError == ERROR_INVALID_PARAMETER &&
		     unParentPidAndFlags == static_cast<u32>( ERecordFlags::NotInSnapshot ) )
			return true;
		unFlags = unParentPidAndFlags | static_cast<u32>( ERecordFlags::OpenFailed );
	}
	else
	{
		++report.m_cOpened;

		// @note / sapdragon: not cleared, a failed name query leaves stack garbage that still goes through the conversion
		wchar_t wszImage[k_cchImagePath];
		const u32 cchImage = g_pImports->GetProcessImageFileNameW( hProcess, wszImage, k_cchImagePath );
		DeviceToDosPath( wszImage );

		FILETIME createTime;
		FILETIME exitTime;
		FILETIME kernelTime;
		FILETIME userTime;
		const BOOL bHaveTimes = g_pImports->GetProcessTimes( hProcess, &createTime, &exitTime, &kernelTime, &userTime );
		g_pImports->CloseHandle( hProcess );

		unFlags = unParentPidAndFlags;
		if ( bHaveTimes )
		{
			memcpy( &ulCreateTime, &createTime, sizeof( ulCreateTime ) );
			if ( exitTime.dwHighDateTime || exitTime.dwLowDateTime )
			{
				if ( !context.m_bIncludeExited )
					return true;
				unFlags |= static_cast<u32>( ERecordFlags::Exited );
			}

			unCreateSeconds = FileTimeToSeconds( ulCreateTime );
			// @note / sapdragon: the clock is only set in ScanPidRange, handle-only pids compare against stack garbage. valve bug, keep it
			if ( context.m_bFilterByAge && context.m_unNowSeconds > unCreateSeconds &&
			     context.m_unNowSeconds - unCreateSeconds > context.m_unMaxAgeSeconds )
			{
				return true;
			}
		}

		char szBaseName[264];
		int cchBaseName = 0;
		if ( cchImage - 1 <= k_cchImagePath - 2 )
		{
			wchar_t *pwszBaseName = const_cast<wchar_t *>( util::wstr::BaseName( wszImage ) );
			// @note / sapdragon: cuts the name off the path, so the "path" hash and string below are the directory only
			if ( pwszBaseName > wszImage )
				pwszBaseName[-1] = 0;
			util::encoding::WideToUtf8Bounded( g_pImports, pwszBaseName, szBaseName, MAX_PATH );
			while ( szBaseName[cchBaseName] )
				++cchBaseName;
		}

		char szDirectory[264];
		util::encoding::WideToUtf8Bounded( g_pImports, wszImage, szDirectory, MAX_PATH );
		int cchDirectory = 0;
		while ( szDirectory[cchDirectory] )
			++cchDirectory;

		if ( context.m_bLimitStrings &&
		     cchBaseName + cchDirectory + context.m_Directories.m_cubUsed + context.m_BaseNames.m_cubUsed + 2 >
		         static_cast<int>( sizeof( ProcessRecord_t ) *
		                           ( ARRAYSIZE( report.m_rgRecords ) - 1 - report.m_cRecords ) ) )
		{
			return false;
		}

		if ( cchBaseName )
		{
			unDirectoryHash = util::hashing::PathHashBytes( reinterpret_cast<const u8 *>( szDirectory ), cchDirectory );
			AddString( context.m_Directories, unDirectoryHash, szDirectory, cchDirectory );
			AppendHash( context.m_DirectoryHashes, unDirectoryHash );

			unBaseNameHash = util::hashing::PathHashBytes( reinterpret_cast<const u8 *>( szBaseName ), cchBaseName );
			AddString( context.m_BaseNames, unBaseNameHash, szBaseName, cchBaseName );
			AppendHash( context.m_BaseNameHashes, unBaseNameHash );
		}
	}

	record.m_unDirectoryHash = unDirectoryHash;
	record.m_unPid = unPid;
	record.m_unBaseNameHash = unBaseNameHash;
	record.m_unParentPidAndFlags = unFlags;
	record.m_unCreateSecondsOrError = ulCreateTime ? unCreateSeconds : unError;
	record.m_unHandleMaskLow = unMaskLow;
	record.m_unHandleMaskHigh = unMaskHigh;
	++report.m_cRecords;
	return true;
}

// @orig: 83 EC ? 53 55 56 57 8D 44 24
void ScanPidRange( ScanContext_t &context ) noexcept
{
	FILETIME now;
	g_pImports->GetSystemTimeAsFileTime( &now );
	u64 ulNow;
	memcpy( &ulNow, &now, sizeof( ulNow ) );

	const u32 unNowSeconds = FileTimeToSeconds( ulNow );
	context.m_pReport->m_unScanTimeSeconds = unNowSeconds;
	context.m_unNowSeconds = unNowSeconds;

	if ( !context.m_cSnapshot )
		return;

	// @note / sapdragon: walks every pid below the highest one in steps of 4, this is how it finds what the snapshot does not list
	u32 unPid = context.m_rgunPids[context.m_cSnapshot - 1];
	int iSnapshot = context.m_cSnapshot - 1;
	while ( iSnapshot >= 0 )
	{
		if ( !unPid || context.m_pReport->m_cRecords >= ARRAYSIZE( context.m_pReport->m_rgRecords ) )
			return;

		u32 unMaskLow = 0;
		u32 unMaskHigh = 0;
		u32 unParentPidAndFlags = static_cast<u32>( ERecordFlags::NotInSnapshot );
		if ( context.m_rgunPids[iSnapshot] == unPid )
		{
			unParentPidAndFlags = context.m_rgunParentPids[iSnapshot];
			unMaskLow = context.m_rgMasks[iSnapshot].m_unLow;
			unMaskHigh = context.m_rgMasks[iSnapshot].m_unHigh;
			--iSnapshot;
		}

		if ( unPid >= context.m_unMinPid && ( unPid <= context.m_unMaxPid || !context.m_unMaxPid ) )
		{
			if ( !CollectProcess( context, unPid, unParentPidAndFlags, unMaskLow, unMaskHigh ) )
				return;
		}
		unPid -= 4;
	}
}

} // namespace

// @orig: 83 EC ? 53 55 56 57 8B E9
void CollectReport( ScanContext_t &context, Report_t &report ) noexcept
{
	int cubPids;
	g_pImports->EnumProcesses( reinterpret_cast<DWORD *>( context.m_rgunPids ), sizeof( context.m_rgunPids ),
	                           reinterpret_cast<DWORD *>( &cubPids ) );
	const int cEnumerated = cubPids / static_cast<int>( sizeof( u32 ) );

	memset( context.m_rgunParentPids, 0, sizeof( context.m_rgunParentPids ) );
	context.m_cSnapshot = EnumerateProcesses( context.m_rgunPids, context.m_rgunParentPids );
	report.m_cEnumerated = cEnumerated;

	int cExtraPids = 0;
	u32 cHandles = 0;
	memset( context.m_rgMasks, 0, sizeof( context.m_rgMasks ) );
	report.m_eHandleQueryStatus =
	    GetSystemHandles( context.m_rgunPids, context.m_cSnapshot, &cExtraPids, &cHandles, context.m_rgMasks );

	// @note / sapdragon: from slot 500 on this reads pids out of the parent list and masks from above the context on the
	// stack, so the report can hold return addresses. only needs a big process list. valve bug, keep it
	for ( int iExtra = 0; iExtra < cExtraPids; ++iExtra )
	{
		const int iPid = context.m_cSnapshot + iExtra;
		CollectProcess( context, context.m_rgunPids[iPid], 0, context.m_rgMasks[iPid].m_unLow,
		                context.m_rgMasks[iPid].m_unHigh );
		if ( report.m_cRecords == ARRAYSIZE( report.m_rgRecords ) )
			break;
	}
	report.m_cExtraPids = cExtraPids;
	report.m_cSystemHandles = cHandles;

	ScanPidRange( context );

	EmitStrings( context.m_BaseNames, context.m_Directories, context.m_DirectoryHashes, context.m_BaseNameHashes,
	             sizeof( ProcessRecord_t ) * ( ARRAYSIZE( report.m_rgRecords ) - report.m_cRecords ),
	             reinterpret_cast<u8 *>( &report.m_rgRecords[report.m_cRecords] ) );

	// @note / sapdragon: the hash vectors only have entries for records with a base name, hence the separate index
	int iHash = 0;
	for ( u32 iRecord = 0; iRecord < report.m_cRecords; ++iRecord )
	{
		ProcessRecord_t &record = report.m_rgRecords[iRecord];
		if ( record.m_unBaseNameHash && !context.m_BaseNameHashes.m_punHashes[iHash] )
			record.m_unParentPidAndFlags |= static_cast<u32>( ERecordFlags::BaseNameEmitted );
		if ( record.m_unDirectoryHash && !context.m_DirectoryHashes.m_punHashes[iHash] )
			record.m_unParentPidAndFlags |= static_cast<u32>( ERecordFlags::DirectoryEmitted );
		if ( record.m_unBaseNameHash )
			++iHash;
	}
}

} // namespace vac::workers::system_handles
