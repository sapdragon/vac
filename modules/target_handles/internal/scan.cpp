// @binary: 762110ce
#include "internal/types.hpp"
#include "bootstrap/bootstrap.hpp"
#include "crt/intrinsics.hpp"
#include "process/process.hpp"
#include "util/encoding.hpp"
#include "util/strings.hpp"

namespace vac::workers::target_handles
{

namespace
{

constexpr u32 k_unSystemHandleInformation = 16;
constexpr u32 k_cchImagePath = MAX_PATH + 1;

#pragma pack( push, 1 )
struct HandleEntry32_t
{
	u32 m_unPidAndBackTrace;
	u8 m_unType;
	u8 m_unAttributes;
	u16 m_unHandle;
	i32 m_nObject;
	u32 m_unGrantedAccess;
};
#pragma pack( pop )
VAC_LAYOUT_SIZE( HandleEntry32_t, 16 );

constinit HandleEntry_t s_ConvertedEntry{};

// @orig: 80 3D ? ? ? ? ? 56
const HandleEntry_t *GetHandleEntry( const u8 *pubHandles, u32 iHandle ) noexcept
{
	if ( g_bUseX64Gate )
		return reinterpret_cast<const HandleEntry_t *>( pubHandles + sizeof( u64 ) +
		                                                iHandle * sizeof( HandleEntry_t ) );

	const auto &entry = reinterpret_cast<const HandleEntry32_t *>( pubHandles + sizeof( u32 ) )[iHandle];
	s_ConvertedEntry.m_unPidAndBackTrace = entry.m_unPidAndBackTrace;
	s_ConvertedEntry.m_unType = entry.m_unType;
	s_ConvertedEntry.m_unAttributes = entry.m_unAttributes;
	s_ConvertedEntry.m_unHandle = entry.m_unHandle;
	s_ConvertedEntry.m_ulObject = static_cast<u64>( static_cast<i64>( entry.m_nObject ) );
	s_ConvertedEntry.m_unGrantedAccess = entry.m_unGrantedAccess;
	return &s_ConvertedEntry;
}

} // namespace

// @orig: inlined
EScanStatus WatchTargetHandles( const Input_t &input, Report_t &report, HANDLE *phProcess, u8 **ppubHandles ) noexcept
{
	g_unQuerySsn = input.m_unQuerySsn;
	g_bUseX64Gate = input.m_unUseX64Gate != 0;
	g_unOpenSsn = input.m_unOpenSsn;

	bool bLowAccess = false;
	EScanStatus eStatus = OpenProcessBySyscall( phProcess, PROCESS_QUERY_LIMITED_INFORMATION, input.m_unTargetPid );
	if ( eStatus != EScanStatus::Ok )
	{
		// @note / sapdragon: compares a win32 code against an ntstatus, real access denied is 0xC0000022 and never takes this fallback
		if ( eStatus != static_cast<EScanStatus>( ERROR_ACCESS_DENIED ) )
			return eStatus;
		eStatus = OpenProcessBySyscall( phProcess, PROCESS_QUERY_INFORMATION, input.m_unTargetPid );
		if ( eStatus != EScanStatus::Ok )
			return eStatus;
		bLowAccess = true;
	}

	if ( reinterpret_cast<uptr>( *phProcess ) > 0xFFFF )
		return EScanStatus::BadHandleValue;

	u32 cubHandles = 0x800000;
	*ppubHandles =
	    static_cast<u8 *>( g_pImports->VirtualAlloc( nullptr, cubHandles, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) );
	if ( !*ppubHandles )
		return static_cast<EScanStatus>( g_pImports->GetLastError() );

	u64 ulTargetObject = 0;
	u8 unTargetType = 0;
	u32 cHandles = 0;
	EScanStatus ePending = EScanStatus::Ok;
	u32 unQuery = 0;
	bool bFirstPass = true;
	const DWORD unStartTick = g_pImports->GetTickCount();

	for ( u32 iPass = 0; iPass < 10; ++iPass )
	{
		if ( g_pImports->GetTickCount() - unStartTick >= 6000 )
		{
			ePending = EScanStatus::Timeout;
			break;
		}

		do
		{
			if ( static_cast<NTSTATUS>( unQuery ) == STATUS_INFO_LENGTH_MISMATCH )
			{
				if ( *ppubHandles )
					g_pImports->VirtualFree( *ppubHandles, 0, MEM_RELEASE );

				// @note / sapdragon: the pointer stays set here, so the cleanup frees it a second time. valve bug, keep it
				if ( cubHandles > 0x3200000 )
					return EScanStatus::HandleBufferLimit;

				cubHandles *= 2;
				*ppubHandles = static_cast<u8 *>(
				    g_pImports->VirtualAlloc( nullptr, cubHandles, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) );
				if ( !*ppubHandles )
					return static_cast<EScanStatus>( g_pImports->GetLastError() );
			}

			if ( !g_unQuerySsn )
				return EScanStatus::NoSyscallNumber;

			if ( g_bUseX64Gate )
			{
				unQuery = NtQuerySystemInformationX64( k_unSystemHandleInformation, PointerToX64( *ppubHandles ),
				                                       cubHandles, 0 );
			}
			else
			{
				unQuery =
				    NtQuerySystemInformationSysenter( k_unSystemHandleInformation, *ppubHandles, cubHandles, nullptr );
			}
		} while ( static_cast<NTSTATUS>( unQuery ) == STATUS_INFO_LENGTH_MISMATCH );

		if ( unQuery )
			return static_cast<EScanStatus>( unQuery );

		cHandles = *reinterpret_cast<const u32 *>( *ppubHandles );

		if ( bFirstPass )
		{
			report.m_cInitialHandles = cHandles;
			// @note / sapdragon: same code for an empty snapshot and for our handle not being in it
			if ( !cHandles )
				return EScanStatus::NoTargetHandle;

			bool bFound = false;
			for ( u32 iHandle = 0; iHandle < cHandles; ++iHandle )
			{
				const HandleEntry_t *pEntry = GetHandleEntry( *ppubHandles, iHandle );
				if ( pEntry->m_unHandle == static_cast<u16>( reinterpret_cast<uptr>( *phProcess ) ) &&
				     pEntry->m_unPidAndBackTrace == g_pImports->GetCurrentProcessId() )
				{
					if ( bFound )
						return EScanStatus::DuplicateHandle;
					bFound = true;
					ulTargetObject = pEntry->m_ulObject;
					unTargetType = pEntry->m_unType;
				}
			}
			if ( !bFound )
				return EScanStatus::NoTargetHandle;
		}

		for ( u32 iHandle = 0; iHandle < cHandles; ++iHandle )
		{
			const HandleEntry_t *pEntry = GetHandleEntry( *ppubHandles, iHandle );
			if ( pEntry->m_ulObject != ulTargetObject || pEntry->m_unType != unTargetType )
				continue;

			const u32 unPid = pEntry->m_unPidAndBackTrace;
			if ( unPid == g_pImports->GetCurrentProcessId() )
				continue;

			u32 iRow = 0;
			while ( iRow < report.m_cRows && ( report.m_rgRows[iRow].m_unPid != unPid ||
			                                   report.m_rgRows[iRow].m_unGrantedAccess != pEntry->m_unGrantedAccess ) )
			{
				++iRow;
			}

			if ( iRow == report.m_cRows )
			{
				if ( report.m_cRows < ARRAYSIZE( report.m_rgRows ) )
				{
					report.m_rgRows[report.m_cRows].m_unPid = unPid;
					report.m_rgRows[report.m_cRows].m_unGrantedAccess = pEntry->m_unGrantedAccess;
					++report.m_cRows;
				}
				else
				{
					ePending = EScanStatus::TooManyRows;
				}
			}
		}

		// @note / sapdragon: leaves an empty row after the first pass, later owners go after it
		if ( bFirstPass && report.m_cRows < ARRAYSIZE( report.m_rgRows ) )
			++report.m_cRows;

		++report.m_cPasses;
		bFirstPass = false;
		g_pImports->SwitchToThread();
	}

	for ( u32 iRow = 0; iRow < report.m_cRows; ++iRow )
	{
		OwnerRow_t &row = report.m_rgRows[iRow];
		if ( !row.m_unPid )
			continue;

		if ( *phProcess )
			g_pImports->CloseHandle( *phProcess );

		const EScanStatus eOpen = OpenProcessBySyscall(
		    phProcess, bLowAccess ? PROCESS_QUERY_INFORMATION | PROCESS_VM_READ : PROCESS_QUERY_LIMITED_INFORMATION,
		    row.m_unPid );
		if ( eOpen != EScanStatus::Ok )
		{
			row.m_eStatus = eOpen;
		}
		else
		{
			wchar_t wszImage[264];
			char szImage[264];
			memset( wszImage, 0, k_cchImagePath * sizeof( wchar_t ) );
			memset( szImage, 0, k_cchImagePath );

			const DWORD cchImage =
			    bLowAccess ? g_pImports->GetModuleFileNameExW( *phProcess, nullptr, wszImage, k_cchImagePath )
			               : g_pImports->GetProcessImageFileNameW( *phProcess, wszImage, k_cchImagePath );
			util::encoding::WideToUtf8Bounded( g_pImports, wszImage, szImage, k_cchImagePath );

			HANDLE hFile = INVALID_HANDLE_VALUE;
			if ( cchImage )
			{
				const u32 cubImage = util::StrLenA( szImage );
				memcpy( row.m_rgchNameTail,
				        cubImage > sizeof( row.m_rgchNameTail ) ? szImage + cubImage - sizeof( row.m_rgchNameTail )
				                                                : szImage,
				        sizeof( row.m_rgchNameTail ) );

				// @note / sapdragon: turns "\Device\" into "\\.\", so byte 4 on is a path CreateFile takes. only for NT paths
				if ( !bLowAccess )
				{
					szImage[4] = '\\';
					szImage[5] = '\\';
					szImage[6] = '.';
				}

				hFile = g_pImports->CreateFileA( bLowAccess ? szImage : szImage + 4, 0,
				                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
				                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
			}

			if ( hFile == INVALID_HANDLE_VALUE )
			{
				row.m_eStatus = static_cast<EScanStatus>( g_pImports->GetLastError() );
			}
			else
			{
				BY_HANDLE_FILE_INFORMATION information;
				if ( g_pImports->GetFileInformationByHandle( hFile, &information ) )
				{
					row.m_unVolumeSerial = information.dwVolumeSerialNumber;
					row.m_unFileIndexLow = information.nFileIndexLow;
					row.m_unFileIndexHigh = information.nFileIndexHigh;
				}
				else
				{
					row.m_eStatus = static_cast<EScanStatus>( g_pImports->GetLastError() );
				}
				g_pImports->CloseHandle( hFile );
			}
		}

		for ( HandleTotal_t &total : report.m_rgTotals )
		{
			if ( row.m_unPid == total.m_unPid )
				break;
			if ( !total.m_unPid )
			{
				total.m_unPid = row.m_unPid;
				// @note / sapdragon: counts every handle of the type in the last snapshot, not only the ones to our target
				for ( u32 iHandle = 0; iHandle < cHandles; ++iHandle )
				{
					const HandleEntry_t *pEntry = GetHandleEntry( *ppubHandles, iHandle );
					if ( pEntry->m_unPidAndBackTrace == total.m_unPid && pEntry->m_unType == unTargetType )
						++total.m_cHandles;
				}
				break;
			}
		}
	}

	return ePending;
}

} // namespace vac::workers::target_handles
