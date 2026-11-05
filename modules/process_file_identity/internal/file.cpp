// @binary: a8848995
#include "internal/types.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/vac_util.hpp"
#include "crt/intrinsics.hpp"
#include "util/encoding.hpp"
#include "util/strings.hpp"

namespace vac::workers::process_file_identity
{

namespace
{

constexpr const wchar_t *k_rgpwszVersionFields[] = {
    L"FileDescription", L"ProductName",     L"InternalName", L"Comments",    L"LegalCopyright",   L"CompanyName",
    L"ProductVersion",  L"LegalTrademarks", L"PrivateBuild", L"FileVersion", L"OriginalFilename", L"SpecialBuild" };

} // namespace

// @orig: FF 74 24 ? 52
int CompareNoCaseN( const wchar_t *pwszA, const wchar_t *pwszB, int cChars ) noexcept
{
	return CompareStringW( LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, pwszA, cChars, pwszB, cChars ) - CSTR_EQUAL;
}

// @note / sapdragon: wcsncpy with its usual traps. always reads cChars from the source and does not terminate
// when the source fills it
// @orig: 53 56 57 8B 7C 24 ? 8B F2
void CopyWideFixed( wchar_t *pwszDst, const wchar_t *pwszSrc, u32 cChars ) noexcept
{
	memcpy( pwszDst, pwszSrc, cChars * sizeof( wchar_t ) );

	const u32 cSource = lstrlenW( pwszSrc );
	if ( cChars > cSource )
		memset( pwszDst + cSource, 0, ( cChars - cSource ) * sizeof( wchar_t ) );
}

// @orig: 53 55 56 8B 35
void CatWideBounded( wchar_t *pwszDst, const wchar_t *pwszSrc, u32 cMaxChars ) noexcept
{
	const u32 cDst = lstrlenW( pwszDst );
	u32 cSrc = lstrlenW( pwszSrc );
	if ( cSrc > cMaxChars )
		cSrc = cMaxChars;

	memcpy( pwszDst + cDst, pwszSrc, cSrc * sizeof( wchar_t ) );
	pwszDst[cSrc + cDst] = 0;
}

// @orig: 52 85 C9 74
void *ReallocateHeap( void *pMemory, usize cubSize ) noexcept
{
	if ( pMemory )
		return ::HeapReAlloc( ::GetProcessHeap(), 0, pMemory, cubSize );
	return ::HeapAlloc( ::GetProcessHeap(), 0, cubSize );
}

// @orig: 51 33 D2 56 BE
u32 BoundedPathLength( const char *pszPath ) noexcept
{
	u32 cChars = 0;
	while ( pszPath[cChars] && cChars < sizeof( FileInput_t::m_szPath ) )
		++cChars;
	return cChars;
}

// @orig: 81 EC ? ? ? ? 53 55 33 C0
bool NtDeviceToDosPath( wchar_t *pwszPath ) noexcept
{
	wchar_t wszDrives[MAX_PATH];
	wszDrives[0] = 0;
	if ( !g_pImports->GetLogicalDriveStringsW( 250, wszDrives ) )
		return false;

	wchar_t wszResult[MAX_PATH];
	wchar_t wszDevice[MAX_PATH];
	wchar_t wszDrive[] = L"C:";
	const wchar_t *pwchDrive = wszDrives;
	wchar_t wchDrive = wszDrives[0];
	u32 cDeviceChars;
	for ( ;; )
	{
		wszDrive[0] = wchDrive;
		if ( g_pImports->QueryDosDeviceW( wszDrive, wszDevice, ARRAYSIZE( wszDevice ) ) )
		{
			cDeviceChars = lstrlenW( wszDevice );
			if ( cDeviceChars < ARRAYSIZE( wszDevice ) && !CompareNoCaseN( pwszPath, wszDevice, cDeviceChars ) )
				break;
		}

		while ( *pwchDrive++ )
			;
		wchDrive = *pwchDrive;
		if ( !wchDrive )
			return false;
	}

	// @note / sapdragon: no bound on the result, a path past the buffer runs over the stack. valve's bug, keep it
	wszResult[0] = 0;
	lstrcatW( wszResult, wszDrive );
	lstrcatW( wszResult, &pwszPath[cDeviceChars] );
	CopyWideFixed( pwszPath, wszResult, k_cPathChars );
	return true;
}

// @orig: 81 EC ? ? ? ? 53 55 56 8D 44 24
u32 CollectVersionStrings( const wchar_t *pwszPath, char *pszOutput ) noexcept
{
	DWORD unHandle = 0;
	const DWORD cubVersion = g_pImports->GetFileVersionInfoSizeW( pwszPath, &unHandle );
	if ( !cubVersion )
		return 0;

	void *pVersion = util::HeapAlloc( cubVersion );
	if ( !pVersion )
		return 0;

	u32 cubLeft = sizeof( ProcessReport_t::m_szVersionStrings );
	u32 cubWritten = 0;
	if ( g_pImports->GetFileVersionInfoW( pwszPath, 0, cubVersion, pVersion ) )
	{
		void *pRoot = nullptr;
		UINT cubRoot = 0;
		if ( g_pImports->VerQueryValueW( pVersion, L"\\", &pRoot, &cubRoot ) )
		{
			void *pTranslations = nullptr;
			UINT cubTranslations = 0;
			if ( g_pImports->VerQueryValueW( pVersion, L"\\VarFileInfo\\Translation", &pTranslations,
			                                 &cubTranslations ) )
			{
				const auto *punTranslations = static_cast<const u16 *>( pTranslations );
				for ( u32 iTranslation = 0; iTranslation < cubTranslations >> 2; ++iTranslation )
				{
					for ( const wchar_t *pwszField : k_rgpwszVersionFields )
					{
						wchar_t wszQuery[200];
						wsprintfW( wszQuery, L"\\StringFileInfo\\%04x%04x\\%s", punTranslations[iTranslation * 2],
						           punTranslations[iTranslation * 2 + 1], pwszField );

						void *pValue = nullptr;
						UINT cValueChars = 0;
						const BOOL bFound = g_pImports->VerQueryValueW( pVersion, wszQuery, &pValue, &cValueChars );

						// @note / sapdragon: the value goes into the query buffer unchecked, so a long version string
						// runs over the stack. valve's bug, keep it
						memcpy( wszQuery, pValue, cValueChars * sizeof( wchar_t ) );
						wszQuery[cValueChars] = 0;
						lstrcatW( wszQuery, L" " );

						if ( bFound && cubLeft > cValueChars + 1 )
						{
							// @note / sapdragon: the capacity is the char count, not the bytes left. utf-8 text gets cut
							util::encoding::WideToUtf8Bounded( g_pImports, wszQuery, pszOutput, cValueChars );

							const u32 cubString = util::StrLenA( pszOutput ) + 1;
							cubLeft -= cubString;
							cubWritten += cubString;
							pszOutput += cubString;
						}
					}
				}
			}
		}
	}

	util::HeapFree( pVersion );
	return cubWritten;
}

// @orig: 81 EC ? ? ? ? 53 8A DA
bool QueryFileIdentity( const wchar_t *pwszPath, bool bDirectory, u32 *punVolume, FileId_t *pFileId ) noexcept
{
	if ( !g_pImports->GetFileInformationByHandle )
		return false;

	const HANDLE hFile =
	    g_pImports->CreateFileW( pwszPath, FILE_GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
	                             bDirectory ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL, nullptr );
	if ( hFile == INVALID_HANDLE_VALUE )
		return false;

	if ( bDirectory )
	{
		// @note / sapdragon: leaves the handle open when the import is missing. same as the original
		if ( !g_pImports->GetFileInformationByHandleEx )
			return false;

		alignas( FILE_ID_BOTH_DIR_INFO ) u8 rgubInfo[132];
		memset( rgubInfo, 0, sizeof( rgubInfo ) );
		const BOOL bQueried =
		    g_pImports->GetFileInformationByHandleEx( hFile, FileIdBothDirectoryInfo, rgubInfo, sizeof( rgubInfo ) );

		*punVolume = 0;
		if ( bQueried && g_pImports->GetVolumeInformationByHandleW )
			g_pImports->GetVolumeInformationByHandleW( hFile, nullptr, 0, reinterpret_cast<LPDWORD>( punVolume ),
			                                           nullptr, nullptr, nullptr, 0 );

		g_pImports->CloseHandle( hFile );
		if ( !bQueried )
		{
			g_pImports->GetLastError();
			return false;
		}

		memcpy( pFileId, &reinterpret_cast<const FILE_ID_BOTH_DIR_INFO *>( rgubInfo )->FileId, sizeof( *pFileId ) );
	}
	else
	{
		BY_HANDLE_FILE_INFORMATION info;
		const BOOL bQueried = g_pImports->GetFileInformationByHandle( hFile, &info );
		g_pImports->CloseHandle( hFile );
		if ( !bQueried )
			return false;

		*punVolume = info.dwVolumeSerialNumber;
		pFileId->m_unLow = info.nFileIndexLow;
		pFileId->m_unHigh = info.nFileIndexHigh;
	}

	return true;
}

} // namespace vac::workers::process_file_identity
