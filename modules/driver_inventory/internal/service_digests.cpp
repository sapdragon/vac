// @binary: 2023d8c3
#include "internal/pe_file.hpp"
#include "internal/string_table.hpp"
#include "internal/types.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/vac_util.hpp"
#include "crt/intrinsics.hpp"
#include "crypto/hash/md5.hpp"
#include "file/file.hpp"
#include "util/encoding.hpp"
#include "util/hashing.hpp"
#include "util/strings.hpp"
#include "util/wstr.hpp"

namespace vac::workers::driver_inventory
{

namespace
{

constexpr u32 k_cubServices = 0x10000;
constexpr u32 k_cubConfig = 0x1000;

constexpr wchar_t k_wszNtPrefix[] = L"\\??\\";
constexpr wchar_t k_wszSystemRoot[] = L"\\SystemRoot";
constexpr wchar_t k_wszSystemDirectory[] = L"\\SystemDirectory";
constexpr wchar_t k_wszWindows[] = L"\\windows";
constexpr wchar_t k_wszSystem32[] = L"system32";
constexpr wchar_t k_wszNative[] = L"native";

// @note / sapdragon: same neighbours as valve's frame, so a path longer than the buffer runs into the reader
struct ImageFrame_t
{
	wchar_t m_wszPath[256];
	CPeFile m_File;
};

wchar_t UpperChar( wchar_t wchChar ) noexcept
{
	return static_cast<wchar_t>(
	    reinterpret_cast<uptr>( CharUpperW( reinterpret_cast<LPWSTR>( static_cast<uptr>( wchChar ) ) ) ) );
}

// @orig: FF 74 24 ? 52
int CompareNoCase( const wchar_t *pwszA, const wchar_t *pwszB, int cChars ) noexcept
{
	return CompareStringW( LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, pwszA, cChars, pwszB, cChars ) - CSTR_EQUAL;
}

// @note / sapdragon: always reads the full 512 bytes of the source first, even past its end
// @orig: 56 57 8B F2 8B F9
void CopyPath( wchar_t *pwszDst, const wchar_t *pwszSrc ) noexcept
{
	memcpy( pwszDst, pwszSrc, sizeof( ImageFrame_t::m_wszPath ) );
	const u32 cChars = util::wstr::Length( pwszSrc );
	if ( cChars < ARRAYSIZE( ImageFrame_t::m_wszPath ) )
		memset( pwszDst + cChars, 0, sizeof( wchar_t ) * ( ARRAYSIZE( ImageFrame_t::m_wszPath ) - cChars ) );
}

// @note / sapdragon: not wstr::Cat, the limit counts what gets added and leaves no room for the terminator
// @orig: 53 55 56 8B 35 ? ? ? ? 8B E9
void AppendPath( wchar_t *pwszDst, const wchar_t *pwszSrc, u32 cMaxChars ) noexcept
{
	const u32 cDst = util::wstr::Length( pwszDst );
	u32 cSrc = util::wstr::Length( pwszSrc );
	if ( cSrc > cMaxChars )
		cSrc = cMaxChars;
	memcpy( pwszDst + cDst, pwszSrc, sizeof( wchar_t ) * cSrc );
	pwszDst[cSrc + cDst] = 0;
}

// @orig: 56 57 8B FA 33 C0
void ExpandServiceImagePath( const wchar_t *pwszImage, wchar_t *pwszOut ) noexcept
{
	*pwszOut = 0;

	int nDifference = 0;
	for ( u32 iChar = 0; iChar < ARRAYSIZE( k_wszNtPrefix ) - 1; ++iChar )
	{
		if ( !pwszImage[iChar] || pwszImage[iChar] != k_wszNtPrefix[iChar] )
		{
			nDifference = pwszImage[iChar] - k_wszNtPrefix[iChar];
			break;
		}
	}
	if ( !nDifference )
	{
		CopyPath( pwszOut, pwszImage + ( ARRAYSIZE( k_wszNtPrefix ) - 1 ) );
		return;
	}

	const wchar_t *pwszRoot;
	u32 cPrefix;
	if ( !CompareNoCase( pwszImage, k_wszSystemRoot, ARRAYSIZE( k_wszSystemRoot ) - 1 ) )
	{
		pwszRoot = g_pSession->m_wszWindowsDirectory;
		cPrefix = ARRAYSIZE( k_wszSystemRoot ) - 1;
	}
	else if ( !CompareNoCase( pwszImage, k_wszSystemDirectory, ARRAYSIZE( k_wszSystemDirectory ) - 1 ) )
	{
		pwszRoot = g_pSession->m_wszSystemDirectory;
		cPrefix = ARRAYSIZE( k_wszSystemDirectory ) - 1;
	}
	else if ( !CompareNoCase( pwszImage, k_wszWindows, ARRAYSIZE( k_wszWindows ) - 1 ) )
	{
		pwszRoot = g_pSession->m_wszWindowsDirectory;
		cPrefix = ARRAYSIZE( k_wszWindows ) - 1;
	}
	else
	{
		CopyPath( pwszOut, pwszImage );
		return;
	}

	CopyPath( pwszOut, pwszRoot );
	AppendPath( pwszOut, pwszImage + cPrefix, ARRAYSIZE( ImageFrame_t::m_wszPath ) - util::wstr::Length( pwszOut ) );
}

// @orig: 83 EC ? 53 55 56 8B 35
wchar_t *FindSystem32( wchar_t *pwszPath ) noexcept
{
	u32 cLeft = util::wstr::Length( pwszPath );
	if ( cLeft < ARRAYSIZE( k_wszSystem32 ) - 1 )
		return nullptr;

	for ( ;; )
	{
		if ( UpperChar( *pwszPath ) == UpperChar( k_wszSystem32[0] ) )
		{
			u32 iChar = 1;
			while ( k_wszSystem32[iChar] && UpperChar( pwszPath[iChar] ) == UpperChar( k_wszSystem32[iChar] ) )
				++iChar;
			if ( !k_wszSystem32[iChar] )
				return pwszPath;
		}

		++pwszPath;
		if ( --cLeft < ARRAYSIZE( k_wszSystem32 ) - 1 )
			return nullptr;
	}
}

// @orig: 55 8B EC A1
bool GetFileId( const SystemImports_t *pImports, const wchar_t *pwszPath, u32 *punVolumeSerial,
                u64 *pulFileId ) noexcept
{
	if ( !pImports->GetFileInformationByHandle )
		return false;

	HANDLE hFile = pImports->CreateFileW( pwszPath, FILE_GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
	                                      FILE_ATTRIBUTE_NORMAL, nullptr );
	if ( hFile == INVALID_HANDLE_VALUE )
		return false;

	BY_HANDLE_FILE_INFORMATION information;
	const BOOL bQueried = pImports->GetFileInformationByHandle( hFile, &information );
	pImports->CloseHandle( hFile );
	if ( !bQueried )
		return false;

	*punVolumeSerial = information.dwVolumeSerialNumber;
	*pulFileId = ( static_cast<u64>( information.nFileIndexHigh ) << 32 ) | information.nFileIndexLow;
	return true;
}

} // namespace

// @orig: 55 8B EC 83 E4 ? B8
EScanStatus CollectServiceImageDigests( ServiceDigestReport_t &report, const SystemImports_t *pImports ) noexcept
{
	EScanStatus eStatus = EScanStatus::Ok;
	SC_HANDLE hService = nullptr;
	QUERY_SERVICE_CONFIGW *pConfig = nullptr;
	ENUM_SERVICE_STATUSW *pServices = nullptr;
	DWORD unResume = 0;
	DWORD cubNeeded;
	DWORD cServices;
	u8 rgubName[64];
	ImageFrame_t frame;

	// @note / sapdragon: built and destroyed, never used. it is in the original too
	StringTable_t rgUnusedTables[3];
	InitStringTable( rgUnusedTables[2] );
	InitStringTable( rgUnusedTables[1] );
	InitStringTable( rgUnusedTables[0] );

	SC_HANDLE hManager = pImports->OpenSCManagerA( nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE );
	if ( !hManager )
	{
		eStatus = static_cast<EScanStatus>( pImports->GetLastError() );
		goto cleanup;
	}

	pServices = static_cast<ENUM_SERVICE_STATUSW *>( util::HeapAlloc( k_cubServices ) );
	if ( !pServices )
	{
		eStatus = EScanStatus::NotEnoughMemory;
		goto cleanup;
	}
	memset( pServices, 0, k_cubServices );

	{
		const BOOL bEnumerated = pImports->EnumServicesStatusW( hManager, SERVICE_DRIVER, SERVICE_ACTIVE, pServices,
		                                                        k_cubServices, &cubNeeded, &cServices, &unResume );
		const u32 unEnumError = pImports->GetLastError();
		if ( !bEnumerated && unEnumError != ERROR_MORE_DATA )
		{
			eStatus = static_cast<EScanStatus>( pImports->GetLastError() );
			goto cleanup;
		}
	}

	report.m_cEntries = 0;
	if ( cServices > ARRAYSIZE( report.m_rgEntries ) )
		cServices = ARRAYSIZE( report.m_rgEntries );

	pConfig = static_cast<QUERY_SERVICE_CONFIGW *>( util::HeapAlloc( k_cubConfig ) );
	if ( !pConfig )
	{
		eStatus = EScanStatus::NotEnoughMemory;
		goto cleanup;
	}

	for ( u32 iService = 0; iService < cServices; ++iService )
	{
		hService = pImports->OpenServiceW( hManager, pServices[iService].lpServiceName,
		                                   SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS );
		if ( !hService || !pImports->QueryServiceConfigW( hService, pConfig, k_cubConfig, &cubNeeded ) )
		{
			eStatus = static_cast<EScanStatus>( pImports->GetLastError() );
			goto cleanup;
		}
		pImports->CloseServiceHandle( hService );
		hService = nullptr;

		// @note / sapdragon: the hash goes in before the file is opened and the slot is reused when that fails,
		// so the last failed service stays visible past the end of the entries
		ServiceDigestEntry_t &entry = report.m_rgEntries[report.m_cEntries];
		util::encoding::WideToUtf8Bounded( pImports, pServices[iService].lpServiceName,
		                                   reinterpret_cast<char *>( rgubName ), sizeof( rgubName ) );
		entry.m_unServiceNameHash =
		    util::hashing::PathHashBytes( rgubName, util::StrLenA( reinterpret_cast<const char *>( rgubName ) ) );

		wchar_t *pwszPath = frame.m_wszPath;
		memset( pwszPath, 0, sizeof( frame.m_wszPath ) );
		ExpandServiceImagePath( pConfig->lpBinaryPathName, pwszPath );

		wchar_t *pwszSystem32 = FindSystem32( pwszPath );
		if ( pwszSystem32 )
		{
			wchar_t *pwszTail = pwszSystem32 + ( ARRAYSIZE( k_wszSystem32 ) - 1 );
			memmove( pwszTail + 1, pwszTail, sizeof( wchar_t ) * util::wstr::Length( pwszTail ) );
			memcpy( pwszSystem32 + 3, k_wszNative, sizeof( wchar_t ) * util::wstr::Length( k_wszNative ) );
		}

		if ( pwszPath[1] != L':' )
		{
			const wchar_t *pwszWindows = g_pSession->m_wszWindowsDirectory;
			const u32 cWindows = util::wstr::Length( pwszWindows );
			memmove( pwszPath + 1 + cWindows, pwszPath, sizeof( wchar_t ) * util::wstr::Length( pwszPath ) );
			memmove( pwszPath, pwszWindows, sizeof( wchar_t ) * cWindows );
			pwszPath[cWindows] = L'\\';
		}

		u32 unVolumeSerial = 0;
		u64 ulFileId = 0;
		if ( !GetFileId( pImports, pwszPath, &unVolumeSerial, &ulFileId ) )
			continue;

		CPeFile &peFile = frame.m_File;
		peFile.Init( pImports );

		// @note / sapdragon: a failed hash leaves status zero and the last error of the open
		u32 unLastError = 0;
		const EScanStatus eOpenStatus = peFile.Open( unVolumeSerial, ulFileId, &unLastError );
		entry.m_unLastError = unLastError;
		entry.m_rgunZero[0] = 0;
		entry.m_rgunZero[1] = 0;
		entry.m_eStatus = eOpenStatus;
		if ( eOpenStatus == EScanStatus::Ok )
		{
			const EScanStatus eParseStatus = peFile.ParseAndAppendOverlay();
			entry.m_eStatus = eParseStatus;
			if ( eParseStatus == EScanStatus::Ok )
			{
				crypto::hash::Md5_t md5;
				u8 rgubDigest[crypto::hash::k_cubMd5Digest];
				if ( peFile.HashHeadersAndSelectedSection( md5, rgubDigest ) )
					memcpy( entry.m_rgubDigest, rgubDigest, sizeof( entry.m_rgubDigest ) );
			}
		}

		const u32 cEntries = ++report.m_cEntries;
		peFile.Reset();
		peFile.Close();
		if ( cEntries >= ARRAYSIZE( report.m_rgEntries ) )
			goto cleanup;
	}

cleanup:
	util::HeapFree( pConfig );
	util::HeapFree( pServices );
	pImports->CloseServiceHandle( hService );
	pImports->CloseServiceHandle( hManager );
	DestroyStringTable( rgUnusedTables[0] );
	DestroyStringTable( rgUnusedTables[1] );
	DestroyStringTable( rgUnusedTables[2] );
	return eStatus;
}

} // namespace vac::workers::driver_inventory
