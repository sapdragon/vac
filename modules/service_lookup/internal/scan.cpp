// @binary: 87f12249
#include "internal/types.hpp"
#include "bootstrap/bootstrap.hpp"
#include "crt/intrinsics.hpp"
#include "util/encoding.hpp"
#include "util/hashing.hpp"
#include "util/strings.hpp"
#include "util/win32.hpp"

namespace vac::workers::service_lookup
{

namespace
{

constexpr u32 k_cchPath = 160;
constexpr u32 k_cubEnumBuffer = 0x10000;
constexpr u32 k_cubConfigBuffer = 0x1000;

constexpr wchar_t k_wszNtPrefix[] = L"\\??\\";
constexpr wchar_t k_wszSystemDirectory[] = L"\\SystemDirectory";
constexpr wchar_t k_wszWindows[] = L"\\windows";
constexpr wchar_t k_wszSystem32[] = L"system32";
constexpr wchar_t k_wszNative[] = L"native";

wchar_t UpperChar( wchar_t wchChar ) noexcept
{
	return static_cast<wchar_t>(
	    reinterpret_cast<uptr>( CharUpperW( reinterpret_cast<LPWSTR>( static_cast<uptr>( wchChar ) ) ) ) );
}

// @orig: FF 74 24 ? 52
int CompareStringPrefix( const wchar_t *pwszA, const wchar_t *pwszB, int cchCount ) noexcept
{
	return CompareStringW( LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, pwszA, cchCount, pwszB, cchCount ) - CSTR_EQUAL;
}

// @orig: 56 57 8B F2 8B F9
wchar_t *CopyPath( wchar_t *pwszDst, const wchar_t *pwszSrc ) noexcept
{
	// @note / sapdragon: always reads 160 chars from the source, whatever its length
	memcpy( pwszDst, pwszSrc, k_cchPath * sizeof( wchar_t ) );
	const u32 cchSrc = lstrlenW( pwszSrc );
	if ( cchSrc < k_cchPath )
		memset( pwszDst + cchSrc, 0, ( k_cchPath - cchSrc ) * sizeof( wchar_t ) );
	return pwszDst;
}

// @orig: 53 55 56 8B 35 ? ? ? ? 8B E9
wchar_t *AppendPath( wchar_t *pwszDst, const wchar_t *pwszSrc, u32 cchMax ) noexcept
{
	const u32 cchDst = lstrlenW( pwszDst );
	u32 cchSrc = lstrlenW( pwszSrc );
	if ( cchSrc > cchMax )
		cchSrc = cchMax;
	memcpy( pwszDst + cchDst, pwszSrc, cchSrc * sizeof( wchar_t ) );
	pwszDst[cchSrc + cchDst] = 0;
	return pwszDst;
}

// @orig: 83 EC ? 53 55 56 8B 35
wchar_t *GetSystem32( wchar_t *pwszPath ) noexcept
{
	wchar_t *pwszChar = pwszPath;
	u32 cchLeft = lstrlenW( pwszPath );
	const u32 cchPattern = lstrlenW( k_wszSystem32 );
	if ( cchLeft < cchPattern )
		return nullptr;

	for ( ;; )
	{
		if ( UpperChar( *pwszChar ) == UpperChar( L's' ) )
		{
			// @note / sapdragon: the text char is compared with 's' a second time, not with the pattern. same result
			const wchar_t *pwszPattern = k_wszSystem32;
			if ( UpperChar( *pwszChar ) == UpperChar( L's' ) )
			{
				for ( ;; )
				{
					++pwszPattern;
					if ( !*pwszPattern )
						return pwszChar;
					if ( UpperChar( pwszChar[pwszPattern - k_wszSystem32] ) != UpperChar( *pwszPattern ) )
						break;
				}
			}
		}

		++pwszChar;
		if ( --cchLeft < cchPattern )
			return nullptr;
	}
}

// @orig: 56 57 8B FA 33 C0
bool FetchSystemDirectories( const wchar_t *pwszPath, wchar_t *pwszOut ) noexcept
{
	*pwszOut = 0;

	int nDiff = 0;
	for ( u32 iChar = 0; iChar < 4; ++iChar )
	{
		const int nChar = pwszPath[iChar];
		if ( !nChar || nChar != k_wszNtPrefix[iChar] )
		{
			nDiff = nChar - k_wszNtPrefix[iChar];
			break;
		}
	}
	if ( !nDiff )
	{
		CopyPath( pwszOut, pwszPath + 4 );
		return true;
	}

	if ( !CompareStringPrefix( pwszPath, L"\\SystemRoot", 11 ) )
	{
		CopyPath( pwszOut, g_pSession->m_wszWindowsDirectory );
		AppendPath( pwszOut, pwszPath + 11, k_cchPath - lstrlenW( pwszOut ) );
		return true;
	}
	if ( !CompareStringPrefix( pwszPath, k_wszSystemDirectory, 16 ) )
	{
		CopyPath( pwszOut, g_pSession->m_wszSystemDirectory );
		AppendPath( pwszOut, pwszPath + 16, k_cchPath - lstrlenW( pwszOut ) );
		return true;
	}
	if ( !CompareStringPrefix( pwszPath, k_wszWindows, 8 ) )
	{
		CopyPath( pwszOut, g_pSession->m_wszWindowsDirectory );
		AppendPath( pwszOut, pwszPath + 8, k_cchPath - lstrlenW( pwszOut ) );
		return true;
	}

	CopyPath( pwszOut, pwszPath );
	return false;
}

// @orig: 55 8B EC A1
bool GetFileInfo( const wchar_t *pwszPath, u32 *punVolumeSerial, void *pFileIndex ) noexcept
{
	if ( !g_pImports->GetFileInformationByHandle )
		return false;

	const HANDLE hFile = g_pImports->CreateFileW( pwszPath, FILE_GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
	                                              FILE_ATTRIBUTE_NORMAL, nullptr );
	if ( hFile == INVALID_HANDLE_VALUE )
		return false;

	BY_HANDLE_FILE_INFORMATION info;
	const BOOL bResult = g_pImports->GetFileInformationByHandle( hFile, &info );
	g_pImports->CloseHandle( hFile );
	if ( !bResult )
		return false;

	*punVolumeSerial = info.dwVolumeSerialNumber;
	memcpy( pFileIndex, &info.nFileIndexLow, sizeof( info.nFileIndexLow ) );
	memcpy( static_cast<u8 *>( pFileIndex ) + sizeof( info.nFileIndexLow ), &info.nFileIndexHigh,
	        sizeof( info.nFileIndexHigh ) );
	return true;
}

} // namespace

// @orig: 81 EC ? ? ? ? 53
EScanStatus ReadServiceInfo( Report_t &report, u32 unServiceNameHash ) noexcept
{
	EScanStatus eStatus = EScanStatus::Ok;
	ENUM_SERVICE_STATUSW *pServices = nullptr;
	QUERY_SERVICE_CONFIGW *pConfig = nullptr;
	SC_HANDLE hService = nullptr;
	DWORD cubNeeded;
	DWORD cServices;
	DWORD unResume = 0;
	char szName[64];
	wchar_t wszPath[k_cchPath];

	const SC_HANDLE hSCManager = g_pImports->OpenSCManagerA( nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE );
	if ( !hSCManager )
	{
		eStatus = static_cast<EScanStatus>( util::GetLastError( g_pImports ) );
		goto exit;
	}

	pServices = static_cast<ENUM_SERVICE_STATUSW *>(
	    g_pImports->HeapAlloc( g_pImports->GetProcessHeap(), 0, k_cubEnumBuffer ) );
	if ( !pServices )
	{
		eStatus = EScanStatus::NotEnoughMemory;
		goto exit;
	}
	memset( pServices, 0, k_cubEnumBuffer );

	{
		// @note / sapdragon: drivers only, and only the running ones
		const BOOL bEnumerated = g_pImports->EnumServicesStatusW( hSCManager, SERVICE_DRIVER, SERVICE_ACTIVE, pServices,
		                                                          k_cubEnumBuffer, &cubNeeded, &cServices, &unResume );
		const DWORD unLastError = util::GetLastError( g_pImports );
		if ( !bEnumerated && unLastError != ERROR_MORE_DATA )
			goto fail;
	}

	pConfig = static_cast<QUERY_SERVICE_CONFIGW *>(
	    g_pImports->HeapAlloc( g_pImports->GetProcessHeap(), 0, k_cubConfigBuffer ) );
	if ( !pConfig )
	{
		eStatus = EScanStatus::NotEnoughMemory;
		goto exit;
	}

	{
		DWORD iService = 0;
		if ( !cServices )
			goto fail;

		const ENUM_SERVICE_STATUSW *pEntry = pServices;
		for ( ;; )
		{
			util::encoding::WideToUtf8Bounded( g_pImports, pEntry->lpServiceName, szName, sizeof( szName ) );
			u32 cchName = 0;
			while ( szName[cchName] )
				++cchName;
			if ( util::hashing::PathHashBytes( reinterpret_cast<const u8 *>( szName ), cchName ) == unServiceNameHash )
				break;

			++iService;
			++pEntry;
			if ( iService >= cServices )
				goto fail;
		}

		hService = g_pImports->OpenServiceW( hSCManager, pServices[iService].lpServiceName,
		                                     SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS );
		if ( !hService || !g_pImports->QueryServiceConfigW( hService, pConfig, k_cubConfigBuffer, &cubNeeded ) )
			goto fail;
		g_pImports->CloseServiceHandle( hService );
		hService = nullptr;

		util::encoding::WideToUtf8Bounded( g_pImports, pServices[iService].lpServiceName, report.m_szServiceName,
		                                   sizeof( report.m_szServiceName ) );
	}

	util::encoding::WideToUtf8Bounded( g_pImports, pConfig->lpDisplayName, report.m_szDisplayName,
	                                   sizeof( report.m_szDisplayName ) );
	report.m_unServiceType = pConfig->dwServiceType;
	report.m_unStartType = pConfig->dwStartType;
	report.m_unErrorControl = pConfig->dwErrorControl;
	FetchSystemDirectories( pConfig->lpBinaryPathName, wszPath );
	util::encoding::WideToUtf8Bounded( g_pImports, wszPath, report.m_szBinaryPath, sizeof( report.m_szBinaryPath ) );
	util::encoding::WideToUtf8Bounded( g_pImports, pConfig->lpLoadOrderGroup, report.m_szLoadOrderGroup,
	                                   sizeof( report.m_szLoadOrderGroup ) );
	util::encoding::WideToUtf8Bounded( g_pImports, pConfig->lpDependencies, report.m_szDependencies,
	                                   sizeof( report.m_szDependencies ) );
	util::encoding::WideToUtf8Bounded( g_pImports, pConfig->lpServiceStartName, report.m_szServiceStartName,
	                                   sizeof( report.m_szServiceStartName ) );

	{
		wchar_t *pwszSystem32 = GetSystem32( wszPath );
		if ( pwszSystem32 )
		{
			const wchar_t *pwszTail = pwszSystem32 + lstrlenW( k_wszSystem32 );
			const u32 cchTail = lstrlenW( pwszTail );
			// @note / sapdragon: the tail moves one char right without its terminator, only the zero fill of the path saves it
			memmove( pwszSystem32 + 9, pwszTail, cchTail * sizeof( wchar_t ) );
			memcpy( pwszSystem32 + 3, k_wszNative, lstrlenW( k_wszNative ) * sizeof( wchar_t ) );
		}
	}

	GetFileInfo( wszPath, &report.m_unVolumeSerial, &report.m_unFileIndexLow );
	goto exit;

fail:
	eStatus = static_cast<EScanStatus>( util::GetLastError( g_pImports ) );

exit:
	g_pImports->HeapFree( g_pImports->GetProcessHeap(), 0, pConfig );
	g_pImports->HeapFree( g_pImports->GetProcessHeap(), 0, pServices );
	g_pImports->CloseServiceHandle( hService );
	g_pImports->CloseServiceHandle( hSCManager );
	return eStatus;
}

} // namespace vac::workers::service_lookup
