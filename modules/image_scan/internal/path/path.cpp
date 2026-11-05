// @binary: 33211402
#include "../scanner.hpp"
#include "bootstrap/bootstrap.hpp"
#include "crt/intrinsics.hpp"
#include "file/file.hpp"
#include "util/xor_string.hpp"

namespace vac::workers::image_scan
{

namespace
{

using PfnWow64DisableWow64FsRedirection_t = BOOL( WINAPI * )( void ** );

} // namespace

// @orig: 33211402:0x1000AC52 (no unique signature)
void *AllocBytes( u32 cub ) noexcept
{
	return HeapAlloc( GetProcessHeap(), 0, cub );
}

// @orig: 33211402:0x1000AC63 (no unique signature)
void FreeBytes( void *pv ) noexcept
{
	HeapFree( GetProcessHeap(), 0, pv );
}

// @orig: 52 85 C9 74
void *ReallocBytes( void *pv, u32 cub ) noexcept
{
	if ( pv )
		return HeapReAlloc( GetProcessHeap(), 0, pv, cub );
	return HeapAlloc( GetProcessHeap(), 0, cub );
}

// @orig: 56 33 F6 57 8B FA
int CompareNameBounded( const char *pszA, const char *pszB, u32 cMaxChars ) noexcept
{
	for ( u32 iChar = 0; iChar < cMaxChars; ++iChar )
	{
		const u8 unA = static_cast<u8>( pszA[iChar] );
		if ( !unA || unA != static_cast<u8>( pszB[iChar] ) )
			return unA - static_cast<u8>( pszB[iChar] );
	}
	return 0;
}

// @orig: 53 55 57 8B E9
int ComparePathPrefix( const wchar_t *pwszA, const wchar_t *pwszB, u32 cMaxChars ) noexcept
{
	u32 cCharsA = static_cast<u32>( lstrlenW( pwszA ) );
	u32 cCharsB = static_cast<u32>( lstrlenW( pwszB ) );
	if ( cCharsA > cMaxChars )
		cCharsA = cMaxChars;
	if ( cCharsB > cMaxChars )
		cCharsB = cMaxChars;
	return CompareStringW( LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, pwszA, static_cast<int>( cCharsA ), pwszB,
	                       static_cast<int>( cCharsB ) ) -
	       CSTR_EQUAL;
}

// @note / sapdragon: not vac::util::wstr::Copy. this reads cChars from the source no matter how short it is, fills
// the rest with zeros and does not terminate a full copy
// @orig: 53 56 57 8B 7C 24 ? 8B F2
void CopyWideFill( wchar_t *pwszDst, const wchar_t *pwszSrc, u32 cChars ) noexcept
{
	memcpy( pwszDst, pwszSrc, cChars * sizeof( wchar_t ) );
	const u32 cCopied = static_cast<u32>( lstrlenW( pwszSrc ) );
	if ( cChars > cCopied )
		memset( pwszDst + cCopied, 0, ( cChars - cCopied ) * sizeof( wchar_t ) );
}

// @orig: 53 55 56 8B 35
static void AppendWideBounded( wchar_t *pwszDst, const wchar_t *pwszSrc, u32 cMaxChars ) noexcept
{
	const u32 cCharsDst = static_cast<u32>( lstrlenW( pwszDst ) );
	u32 cCharsSrc = static_cast<u32>( lstrlenW( pwszSrc ) );
	if ( cCharsSrc > cMaxChars )
		cCharsSrc = cMaxChars;
	memcpy( pwszDst + cCharsDst, pwszSrc, cCharsSrc * sizeof( wchar_t ) );
	pwszDst[cCharsDst + cCharsSrc] = 0;
}

// @orig: 53 56 57 8B FA
bool ResolveSpecialPath( const wchar_t *pwszPath, wchar_t *pwszResolved ) noexcept
{
	constexpr wchar_t k_wszNtPrefix[] = L"\\??\\";

	*pwszResolved = 0;

	u32 iChar = 0;
	while ( iChar < 4 && pwszPath[iChar] && pwszPath[iChar] == k_wszNtPrefix[iChar] )
		++iChar;
	if ( iChar == 4 )
	{
		CopyWideFill( pwszResolved, pwszPath + 4, MAX_PATH );
		return true;
	}

	const wchar_t *pwszRest;
	if ( !ComparePathPrefix( pwszPath, L"\\SystemRoot", 11 ) )
	{
		CopyWideFill( pwszResolved, g_pSession->m_wszWindowsDirectory, MAX_PATH );
		pwszRest = pwszPath + 11;
	}
	else if ( !ComparePathPrefix( pwszPath, L"\\SystemDirectory", 16 ) )
	{
		CopyWideFill( pwszResolved, g_pSession->m_wszSystemDirectory, MAX_PATH );
		pwszRest = pwszPath + 16;
	}
	else if ( !ComparePathPrefix( pwszPath, L"\\windows", 8 ) )
	{
		CopyWideFill( pwszResolved, g_pSession->m_wszWindowsDirectory, MAX_PATH );
		pwszRest = pwszPath + 8;
	}
	else
	{
		CopyWideFill( pwszResolved, pwszPath, MAX_PATH );
		return false;
	}

	AppendWideBounded( pwszResolved, pwszRest, MAX_PATH - static_cast<u32>( lstrlenW( pwszResolved ) ) );
	return true;
}

// @orig: 81 EC ? ? ? ? 53 55 33 C0
bool DevicePathToDos( wchar_t *pwszPath ) noexcept
{
	wchar_t wszDrives[MAX_PATH];
	wszDrives[0] = 0;
	if ( !g_pImports->GetLogicalDriveStringsW( 250, wszDrives ) )
		return false;

	wchar_t wszDevice[MAX_PATH];
	wchar_t wszDrive[] = L"C:";
	const wchar_t *pwszDrive = wszDrives;
	u32 cDeviceChars;
	for ( ;; )
	{
		wszDrive[0] = *pwszDrive;
		if ( g_pImports->QueryDosDeviceW( wszDrive, wszDevice, ARRAYSIZE( wszDevice ) ) )
		{
			cDeviceChars = static_cast<u32>( lstrlenW( wszDevice ) );
			if ( cDeviceChars < ARRAYSIZE( wszDevice ) && !ComparePathPrefix( pwszPath, wszDevice, cDeviceChars ) )
				break;
		}

		while ( *pwszDrive++ )
			;
		if ( !*pwszDrive )
			return false;
	}

	wchar_t wszResolved[MAX_PATH];
	wszResolved[0] = 0;
	lstrcatW( wszResolved, wszDrive );
	lstrcatW( wszResolved, pwszPath + cDeviceChars );
	CopyWideFill( pwszPath, wszResolved, MAX_PATH );
	return true;
}

// @note / sapdragon: the cookie is never handed back, the worker returns with redirection off
// @orig: 55 8B EC 83 EC ? 6A
bool DisableWow64FsRedirection() noexcept
{
	auto szDisable = util::MakeXorString<0x37>( "Wow64DisableWow64FsRedirection" );
	szDisable.Decode();

	const HMODULE hKernel32 = g_pImports->GetModuleHandleA( "kernel32.dll" );
	if ( !hKernel32 )
		return false;

	const auto pfnDisable = reinterpret_cast<PfnWow64DisableWow64FsRedirection_t>(
	    g_pImports->GetProcAddress( hKernel32, szDisable.Get() ) );
	if ( !pfnDisable )
		return false;

	void *pvCookie;
	pfnDisable( &pvCookie );
	return true;
}

// @orig: 55 8B EC A1
bool GetFileVolumeAndIndex( const wchar_t *pwszPath, u32 *punVolumeSerial, u64 *pulFileIndex ) noexcept
{
	if ( !g_pImports->GetFileInformationByHandle )
		return false;

	const HANDLE hFile = g_pImports->CreateFileW( pwszPath, FILE_GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
	                                              FILE_ATTRIBUTE_NORMAL, nullptr );
	if ( hFile == INVALID_HANDLE_VALUE )
		return false;

	BY_HANDLE_FILE_INFORMATION info;
	const BOOL bOk = g_pImports->GetFileInformationByHandle( hFile, &info );
	g_pImports->CloseHandle( hFile );
	if ( !bOk )
		return false;

	*punVolumeSerial = info.dwVolumeSerialNumber;
	*pulFileIndex = ( static_cast<u64>( info.nFileIndexHigh ) << 32 ) | info.nFileIndexLow;
	return true;
}

} // namespace vac::workers::image_scan
