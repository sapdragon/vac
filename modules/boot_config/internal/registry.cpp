// @binary: 2909d63a
#include "internal/types.hpp"
#include "bootstrap/bootstrap.hpp"
#include "crt/intrinsics.hpp"
#include "util/hashing.hpp"
#include "util/strings.hpp"

namespace vac::workers::boot_config
{

namespace
{

constexpr u32 k_cchPathMax = 0xFFFF;

// @orig: 53 56 57 8B D9 E8
char *ConcatPath( char *pszDst, const char *pszSrc ) noexcept
{
	const u32 cchDst = util::StrLenA( pszDst );
	u32 cchSrc = util::StrLenA( pszSrc );
	if ( cchSrc > k_cchPathMax )
		cchSrc = k_cchPathMax;
	memcpy( pszDst + cchDst, pszSrc, cchSrc );
	pszDst[cchDst + cchSrc] = 0;
	return pszDst;
}

} // namespace

// @orig: 55 8B EC 81 EC
int ReadElement( char *pszKeyPath, const char *pszElementId, const char *pszValueName, bool bFileCheck,
                 Element_t *pElement, u32 *punHash ) noexcept
{
	char szValue[260];
	char szPath[520];
	BY_HANDLE_FILE_INFORMATION info;
	HKEY hKey;

	memcpy( pszKeyPath + offsetof( KeyPath_t, m_rgchElementId ), pszElementId, sizeof( KeyPath_t::m_rgchElementId ) );
	LSTATUS nStatus = g_pImports->RegOpenKeyExA( HKEY_LOCAL_MACHINE, pszKeyPath, 0, KEY_QUERY_VALUE, &hKey );
	pElement->m_ubOpenStatus = static_cast<u8>( nStatus );
	if ( nStatus )
		return nStatus;

	DWORD cubValue = sizeof( szValue );
	nStatus = g_pImports->RegQueryValueExA( hKey, pszValueName, nullptr, nullptr, reinterpret_cast<LPBYTE>( szValue ),
	                                        &cubValue );
	pElement->m_ubQueryStatus = static_cast<u8>( nStatus );
	if ( nStatus )
	{
		g_pImports->RegCloseKey( hKey );
		return nStatus;
	}

	szValue[sizeof( szValue ) - 1] = 0;
	const int cchValue = static_cast<int>( util::StrLenA( szValue ) );
	const int cchFree = static_cast<int>( sizeof( pElement->m_szValue ) ) - pElement->m_cubValue;
	if ( cchValue <= cchFree )
	{
		memcpy( pElement->m_szValue + pElement->m_cubValue, szValue, cchValue );
		pElement->m_cubValue += static_cast<u8>( cchValue );
		if ( pElement->m_cubValue < sizeof( pElement->m_szValue ) )
		{
			pElement->m_szValue[pElement->m_cubValue] = 0;
			++pElement->m_cubValue;
		}
	}
	else if ( cchFree > 0 )
	{
		// @note / sapdragon: when it does not fit it keeps the end of the text, not the start
		memcpy( pElement->m_szValue + pElement->m_cubValue, szValue + ( cchValue - cchFree ), cchFree );
		pElement->m_cubValue += static_cast<u8>( cchFree );
	}

	if ( punHash && cchValue )
		*punHash = util::hashing::PathHashBytes( reinterpret_cast<const u8 *>( szValue ), cchValue );

	if ( g_pImports->GetSystemDirectoryA( szPath, sizeof( szPath ) ) && bFileCheck )
	{
		ConcatPath( szPath, "\\" );
		if ( szValue[0] == '\\' )
			util::CopyA( szPath + 2, szValue, k_cchPathMax );
		else
			ConcatPath( szPath, szValue );

		const HANDLE hFile = g_pImports->CreateFileA( szPath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		                                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
		if ( hFile == INVALID_HANDLE_VALUE )
		{
			pElement->m_ubFileOpenError = static_cast<u8>( g_pImports->GetLastError() );
		}
		else
		{
			if ( g_pImports->GetFileInformationByHandle( hFile, &info ) )
			{
				pElement->m_unFileIndexLow = info.nFileIndexLow;
				pElement->m_unFileIndexHigh = info.nFileIndexHigh;
			}
			else
			{
				pElement->m_ubFileInfoError = static_cast<u8>( g_pImports->GetLastError() );
			}
			g_pImports->CloseHandle( hFile );
		}
	}

	g_pImports->RegCloseKey( hKey );
	return nStatus;
}

// @orig: 81 EC ? ? ? ? 53 55 56 57 33 DB
void EnumerateObjects( Report_t &report, char *pszKeyPath, const char *pszValueName ) noexcept
{
	char szObjectsPath[sizeof( KeyPath_t::m_rgchObjects ) + 2]{};
	char szClass[260]{};
	char szSubKey[500];
	FILETIME ftSubKey;
	DWORD cchClass = sizeof( szClass );
	DWORD cSubKeys = 0;
	DWORD cchMaxSubKey, cchMaxClass, cValues, cchMaxValueName, cubMaxValue, cubSecurity;
	HKEY hKey = nullptr;

	memcpy( szObjectsPath, pszKeyPath, sizeof( KeyPath_t::m_rgchObjects ) );
	report.m_unObjectsOpenStatus = g_pImports->RegOpenKeyExA( HKEY_LOCAL_MACHINE, szObjectsPath, 0, KEY_READ, &hKey );
	if ( report.m_unObjectsOpenStatus )
		return;

	report.m_unObjectsQueryStatus = g_pImports->RegQueryInfoKeyA(
	    hKey, szClass, &cchClass, nullptr, &cSubKeys, &cchMaxSubKey, &cchMaxClass, &cValues, &cchMaxValueName,
	    &cubMaxValue, &cubSecurity, &report.m_ftObjectsLastWrite );
	report.m_cSubKeys = cSubKeys;
	report.m_cValues = cValues;
	if ( !cSubKeys )
		return;

	for ( DWORD iSubKey = 0; iSubKey < cSubKeys; ++iSubKey )
	{
		DWORD cchSubKey = sizeof( szSubKey );
		if ( g_pImports->RegEnumKeyExA( hKey, iSubKey, szSubKey, &cchSubKey, nullptr, nullptr, nullptr, &ftSubKey ) )
			continue;

		u32 cObjects = report.m_cObjects;
		if ( cObjects < ARRAYSIZE( report.m_rgObjects ) )
		{
			memcpy( pszKeyPath + offsetof( KeyPath_t, m_rgchGuid ), szSubKey + 1, sizeof( KeyPath_t::m_rgchGuid ) );
			memcpy( report.m_rgszObjectGuid[report.m_cObjects], szSubKey + 1, sizeof( report.m_rgszObjectGuid[0] ) );

			Element_t *pObject = &report.m_rgObjects[report.m_cObjects];
			ReadElement( pszKeyPath, "12000002", pszValueName, true, pObject, &pObject->m_unPathHash );
			ReadElement( pszKeyPath, "12000004", pszValueName, false, pObject, &pObject->m_unDescriptionHash );
			cObjects = report.m_cObjects;
		}
		report.m_cObjects = cObjects + 1;
	}
}

} // namespace vac::workers::boot_config
