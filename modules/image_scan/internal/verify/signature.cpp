// @binary: 33211402
#include "../scanner.hpp"
#include "bootstrap/bootstrap.hpp"
#include "crt/intrinsics.hpp"
#include "util/encoding.hpp"
#include "verify/cert_chain.hpp"

#include <SoftPub.h>
#include <mscat.h>

namespace vac::workers::image_scan
{

namespace
{

using PfnCryptCATAdminAcquireContext_t = BOOL( WINAPI * )( HCATADMIN *, const GUID *, DWORD );
using PfnCryptCATAdminAcquireContext2_t = BOOL( WINAPI * )( HCATADMIN *, const GUID *, PCWSTR, void *, DWORD );
using PfnCryptCATAdminCalcHashFromFileHandle_t = BOOL( WINAPI * )( HANDLE, DWORD *, BYTE *, DWORD );
using PfnCryptCATAdminCalcHashFromFileHandle2_t = BOOL( WINAPI * )( HCATADMIN, HANDLE, DWORD *, BYTE *, DWORD );
using PfnCryptCATAdminReleaseContext_t = BOOL( WINAPI * )( HCATADMIN, DWORD );
using PfnCryptCATAdminEnumCatalogFromHash_t = HCATINFO( WINAPI * )( HCATADMIN, BYTE *, DWORD, DWORD, HCATINFO * );
using PfnCryptCATCatalogInfoFromContext_t = BOOL( WINAPI * )( HCATINFO, CATALOG_INFO *, DWORD );
using PfnCryptCATAdminReleaseCatalogContext_t = BOOL( WINAPI * )( HCATADMIN, HCATINFO, DWORD );

constinit PfnCryptCATAdminAcquireContext_t s_pfnAcquireContext = nullptr;
constinit PfnCryptCATAdminAcquireContext2_t s_pfnAcquireContext2 = nullptr;
constinit PfnCryptCATAdminCalcHashFromFileHandle_t s_pfnCalcHash = nullptr;
constinit PfnCryptCATAdminCalcHashFromFileHandle2_t s_pfnCalcHash2 = nullptr;
constinit PfnCryptCATAdminReleaseContext_t s_pfnReleaseContext = nullptr;
constinit PfnCryptCATAdminEnumCatalogFromHash_t s_pfnEnumCatalog = nullptr;
constinit PfnCryptCATCatalogInfoFromContext_t s_pfnCatalogInfo = nullptr;
constinit PfnCryptCATAdminReleaseCatalogContext_t s_pfnReleaseCatalog = nullptr;

constexpr GUID k_DriverActionVerify = DRIVER_ACTION_VERIFY;

struct FileView_t
{
	HANDLE m_hMapping;
	void *m_pView;
	u64 m_cubFile;
	u32 m_unLastError;
};

#pragma pack( push, 1 )
struct CatalogLookup_t
{
	HCATADMIN m_hAdmin;
	HCATINFO m_hCatalog;
	BYTE *m_pubHash;
	DWORD m_cubHash;
	WINTRUST_CATALOG_INFO m_CatalogInfo;
	CATALOG_INFO m_Info;
};
#pragma pack( pop )
VAC_LAYOUT( CatalogLookup_t, m_CatalogInfo, 0x10 );
VAC_LAYOUT( CatalogLookup_t, m_Info, 0x34 );
VAC_LAYOUT_SIZE( WINTRUST_DATA, 48 );

// @orig: 56 8B F1 57 33 FF 8D 46
void OpenFileView( FileView_t *pView, HANDLE hFile ) noexcept
{
	pView->m_hMapping = nullptr;
	pView->m_cubFile = 0;
	pView->m_pView = nullptr;
	g_pImports->GetFileSizeEx( hFile, reinterpret_cast<PLARGE_INTEGER>( &pView->m_cubFile ) );

	pView->m_hMapping = g_pImports->CreateFileMappingW( hFile, nullptr, PAGE_READONLY, 0, 0, nullptr );
	if ( !pView->m_hMapping ||
	     !( pView->m_pView = g_pImports->MapViewOfFile( pView->m_hMapping, FILE_MAP_READ, 0, 0, 0 ) ) )
		pView->m_unLastError = g_pImports->GetLastError();
}

// @orig: 56 8B F1 83 7E ? ? 74 ? A1 ? ? ? ? FF 76
void CloseFileView( const FileView_t *pView ) noexcept
{
	if ( pView->m_pView )
		g_pImports->UnmapViewOfFile( pView->m_pView );
	if ( pView->m_hMapping )
		g_pImports->CloseHandle( pView->m_hMapping );
}

// @note / sapdragon: the library handle is never freed, the catalog functions stay valid for the next call
// @orig: A1 ? ? ? ? 56 68
bool LoadCatalogFunctions() noexcept
{
	const HMODULE hWinTrust = g_pImports->LoadLibraryA( "wintrust.dll" );
	if ( !hWinTrust )
		return false;

	s_pfnAcquireContext = reinterpret_cast<PfnCryptCATAdminAcquireContext_t>(
	    g_pImports->GetProcAddress( hWinTrust, "CryptCATAdminAcquireContext" ) );
	s_pfnAcquireContext2 = reinterpret_cast<PfnCryptCATAdminAcquireContext2_t>(
	    g_pImports->GetProcAddress( hWinTrust, "CryptCATAdminAcquireContext2" ) );
	s_pfnCalcHash = reinterpret_cast<PfnCryptCATAdminCalcHashFromFileHandle_t>(
	    g_pImports->GetProcAddress( hWinTrust, "CryptCATAdminCalcHashFromFileHandle" ) );
	s_pfnCalcHash2 = reinterpret_cast<PfnCryptCATAdminCalcHashFromFileHandle2_t>(
	    g_pImports->GetProcAddress( hWinTrust, "CryptCATAdminCalcHashFromFileHandle2" ) );
	s_pfnReleaseContext = reinterpret_cast<PfnCryptCATAdminReleaseContext_t>(
	    g_pImports->GetProcAddress( hWinTrust, "CryptCATAdminReleaseContext" ) );
	s_pfnEnumCatalog = reinterpret_cast<PfnCryptCATAdminEnumCatalogFromHash_t>(
	    g_pImports->GetProcAddress( hWinTrust, "CryptCATAdminEnumCatalogFromHash" ) );
	s_pfnCatalogInfo = reinterpret_cast<PfnCryptCATCatalogInfoFromContext_t>(
	    g_pImports->GetProcAddress( hWinTrust, "CryptCATCatalogInfoFromContext" ) );
	s_pfnReleaseCatalog = reinterpret_cast<PfnCryptCATAdminReleaseCatalogContext_t>(
	    g_pImports->GetProcAddress( hWinTrust, "CryptCATAdminReleaseCatalogContext" ) );
	return true;
}

// @note / sapdragon: the hash buffer is never freed, and a second failure of the old API leaks it right here
// @orig: 56 8B F1 8B 06
void CloseCatalogLookup( const CatalogLookup_t *pLookup ) noexcept
{
	if ( !pLookup->m_hAdmin )
		return;
	if ( pLookup->m_hCatalog )
		s_pfnReleaseCatalog( pLookup->m_hAdmin, pLookup->m_hCatalog, 0 );
	s_pfnReleaseContext( pLookup->m_hAdmin, 0 );
}

// @orig: 55 8B EC 51 56 57
bool CalcCatalogHash( const CatalogLookup_t *pLookup, HANDLE hFile, BYTE **ppubHash, DWORD *pcubHash ) noexcept
{
	DWORD cubHash = 32;
	BYTE *pubHash = static_cast<BYTE *>( AllocBytes( 32 ) );
	if ( s_pfnCalcHash2 )
	{
		if ( !s_pfnCalcHash2( pLookup->m_hAdmin, hFile, &cubHash, pubHash, 0 ) )
		{
			FreeBytes( pubHash );
			pubHash = static_cast<BYTE *>( AllocBytes( cubHash ) );
			if ( !s_pfnCalcHash2( pLookup->m_hAdmin, hFile, &cubHash, pubHash, 0 ) )
			{
				FreeBytes( pubHash );
				return false;
			}
		}
	}
	else if ( !s_pfnCalcHash( hFile, &cubHash, pubHash, 0 ) )
	{
		FreeBytes( pubHash );
		pubHash = static_cast<BYTE *>( AllocBytes( cubHash ) );
		if ( !s_pfnCalcHash( hFile, &cubHash, pubHash, 0 ) )
			return false;
	}

	*ppubHash = pubHash;
	*pcubHash = cubHash;
	return true;
}

// @note / sapdragon: the struct size written below is the size of the catalog path buffer, not of the struct. keep it
// @orig: 53 55 56 57 8B F1 E8 ? ? ? ? 84 C0
bool FindCatalogForFile( CatalogLookup_t *pLookup, HANDLE hFile ) noexcept
{
	if ( !LoadCatalogFunctions() )
		return false;

	BOOL bAcquired;
	if ( s_pfnAcquireContext2 )
	{
		bAcquired = s_pfnAcquireContext2( &pLookup->m_hAdmin, &k_DriverActionVerify, nullptr, nullptr, 0 );
	}
	else
	{
		if ( !s_pfnAcquireContext )
			return false;
		bAcquired = s_pfnAcquireContext( &pLookup->m_hAdmin, &k_DriverActionVerify, 0 );
	}
	if ( !bAcquired )
		return false;

	if ( CalcCatalogHash( pLookup, hFile, &pLookup->m_pubHash, &pLookup->m_cubHash ) && s_pfnEnumCatalog )
		pLookup->m_hCatalog = s_pfnEnumCatalog( pLookup->m_hAdmin, pLookup->m_pubHash, pLookup->m_cubHash, 0, nullptr );

	if ( !pLookup->m_hCatalog || !s_pfnCatalogInfo || !s_pfnCatalogInfo( pLookup->m_hCatalog, &pLookup->m_Info, 0 ) )
		return false;

	pLookup->m_CatalogInfo.cbStruct = sizeof( pLookup->m_Info );
	pLookup->m_CatalogInfo.pcwszCatalogFilePath = pLookup->m_Info.wszCatalogFile;
	pLookup->m_CatalogInfo.pbCalculatedFileHash = pLookup->m_pubHash;
	pLookup->m_CatalogInfo.cbCalculatedFileHash = pLookup->m_cubHash;
	pLookup->m_CatalogInfo.pcwszMemberFilePath = nullptr;
	pLookup->m_CatalogInfo.pcwszMemberTag = nullptr;
	return true;
}

} // namespace

// @orig: 81 EC ? ? ? ? 53 55 56 8B F1
bool VerifySignatureAndCatalog( ScannerContext_t *pCtx, bool bLookUpCatalog ) noexcept
{
	pCtx->m_unWinTrustStatus = 0;
	pCtx->m_unWinTrustLastError = ERROR_INVALID_HANDLE;
	if ( pCtx->m_hFile == INVALID_HANDLE_VALUE )
		return false;

	WINTRUST_FILE_INFO fileInfo;
	memset( &fileInfo, 0, sizeof( fileInfo ) );
	fileInfo.cbStruct = sizeof( fileInfo );
	fileInfo.hFile = pCtx->m_hFile;
	fileInfo.pcwszFilePath = L"";

	GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	WINTRUST_DATA data;
	memset( &data, 0, sizeof( data ) );
	data.cbStruct = sizeof( data );
	data.fdwRevocationChecks = WTD_REVOKE_NONE;
	data.dwStateAction = WTD_STATEACTION_VERIFY;
	data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
	data.dwUIChoice = WTD_UI_NONE;

	CatalogLookup_t lookup;
	memset( &lookup, 0, sizeof( lookup ) );
	pCtx->m_bCatalogValid = 0;
	pCtx->m_szCatalogPath[0] = 0;

	if ( bLookUpCatalog && FindCatalogForFile( &lookup, pCtx->m_hFile ) )
	{
		pCtx->m_bCatalogValid = 1;
		if ( lookup.m_CatalogInfo.pcwszCatalogFilePath )
		{
			util::encoding::WideToUtf8Bounded( g_pImports, lookup.m_CatalogInfo.pcwszCatalogFilePath,
			                                   pCtx->m_szCatalogPath, sizeof( pCtx->m_szCatalogPath ) );
			pCtx->m_szCatalogPath[sizeof( pCtx->m_szCatalogPath ) - 1] = 0;
		}
		data.dwUnionChoice = WTD_CHOICE_CATALOG;
		data.pCatalog = &lookup.m_CatalogInfo;
	}
	else
	{
		data.dwUnionChoice = WTD_CHOICE_FILE;
		data.pFile = &fileInfo;
	}

	pCtx->m_unWinTrustStatus = static_cast<u32>( g_pImports->WinVerifyTrust( nullptr, &action, &data ) );
	pCtx->m_unWinTrustLastError = g_pImports->GetLastError();

	memset( &pCtx->m_Signer, 0, sizeof( pCtx->m_Signer ) );
	memset( &pCtx->m_Issuer, 0, sizeof( pCtx->m_Issuer ) );
	pCtx->m_unMappingLastError = 0;
	pCtx->m_unCertLastError = 0;

	FileView_t view;
	OpenFileView( &view, pCtx->m_hFile );
	if ( view.m_pView )
	{
		verify::CertContextSet_t certificates;
		(void)verify::OpenCertificateContextFromBlob( g_pImports, &certificates, view.m_pView,
		                                              static_cast<u32>( view.m_cubFile ),
		                                              CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED );
		if ( certificates.m_hMsg )
			verify::ExtractCertChain( g_pImports, &certificates, &pCtx->m_Signer, &pCtx->m_Issuer );
		else
			pCtx->m_unCertLastError = certificates.m_unLastError;
		verify::ReleaseCertContext( g_pImports, &certificates );
	}
	else
	{
		pCtx->m_unMappingLastError = view.m_unLastError;
	}

	data.dwStateAction = WTD_STATEACTION_CLOSE;
	g_pImports->WinVerifyTrust( nullptr, &action, &data );
	CloseFileView( &view );
	CloseCatalogLookup( &lookup );
	return true;
}

} // namespace vac::workers::image_scan
