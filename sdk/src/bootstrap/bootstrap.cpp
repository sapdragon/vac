// @binary: 9b85c913
#include "bootstrap/bootstrap.hpp"
#include "bootstrap/blob.hpp"
#include "crt/intrinsics.hpp"
#include "crypto/hash/hash488781ed.hpp"
#include "crypto/ice/ice.hpp"

namespace vac
{

namespace
{

constinit SystemImports_t s_Imports{};
constinit ModuleSession_t s_Session{};

} // namespace

constinit SystemImports_t *const g_pImports = &s_Imports;
constinit ModuleSession_t *const g_pSession = &s_Session;
constinit u32 g_unIntegrityHash = 0;

} // namespace vac

namespace vac::bootstrap
{

namespace
{

constinit u32 s_cResolvedImports = 0;
constinit u32 s_cLoadedLibraries = 0;
constinit u32 s_rgibLoadedLibraryNames[16]{};
constinit HMODULE s_rghLoadedLibraries[16]{};
constinit BootstrapBlob_t s_Blob{};

const char *BlobString( u32 ibString ) noexcept
{
	return reinterpret_cast<const char *>( s_Blob.m_rgub + ibString );
}

// @orig: 83 3D ? ? ? ? ? 53
bool ResolveAllImports() noexcept
{
	const ImportEntry_t *pEntry = k_BlobImage.m_rgEntries;
	void **ppfnImport = reinterpret_cast<void **>( &s_Imports );

	if ( !pEntry->m_ibLibrary )
		return false;

	while ( s_cResolvedImports < sizeof( s_Imports ) / sizeof( void * ) )
	{
		u32 iLibrary = 0;
		while ( iLibrary < s_cLoadedLibraries && s_rgibLoadedLibraryNames[iLibrary] != pEntry->m_ibLibrary )
			++iLibrary;

		HMODULE hLibrary;
		if ( iLibrary < s_cLoadedLibraries )
		{
			hLibrary = s_rghLoadedLibraries[iLibrary];
		}
		else
		{
			if ( s_cLoadedLibraries >= ARRAYSIZE( s_rghLoadedLibraries ) )
				return false;

			hLibrary = g_pImports->LoadLibraryExA( BlobString( pEntry->m_ibLibrary ), nullptr, 0 );
			s_rghLoadedLibraries[s_cLoadedLibraries] = hLibrary;
			if ( hLibrary )
			{
				s_rgibLoadedLibraryNames[s_cLoadedLibraries] = pEntry->m_ibLibrary;
				++s_cLoadedLibraries;
			}
		}

		if ( hLibrary && pEntry->m_ibFunction )
		{
			*ppfnImport =
			    reinterpret_cast<void *>( g_pImports->GetProcAddress( hLibrary, BlobString( pEntry->m_ibFunction ) ) );
		}

		++pEntry;
		++ppfnImport;
		++s_cResolvedImports;
		if ( !pEntry->m_ibLibrary )
			return true;
	}
	return false;
}

// @orig: 9b85c913:0x10004ADD (no unique signature)
bool VerifyCriticalApis() noexcept
{
	return s_Imports.CreateFileA && s_Imports.OpenProcess && s_Imports.CloseHandle && s_Imports.ReadProcessMemory &&
	       s_Imports.VirtualQuery && s_Imports.VirtualQueryEx && s_Imports.EnumProcesses && s_Imports.LoadLibraryA &&
	       s_Imports.LoadLibraryExA && s_Imports.VirtualAlloc && s_Imports.GetModuleHandleA &&
	       s_Imports.GetModuleFileNameA && s_Imports.GetCurrentProcess && s_Imports.GetCurrentProcessId &&
	       s_Imports.GetLastError && s_Imports.GetSystemInfo && s_Imports.GetSystemDirectoryA &&
	       s_Imports.GetWindowsDirectoryA && s_Imports.GetVersionExA && s_Imports.ReadFile && s_Imports.FreeLibrary &&
	       s_Imports.GetProcAddress && s_Imports.NtQueryInformationProcess && s_Imports.NtQuerySystemInformation &&
	       s_Imports.GetProcessTimes;
}

// @orig: 51 A1
bool CollectSystemInfo() noexcept
{
	ModuleSession_t *pSession = g_pSession;

	pSession->m_unPid = g_pImports->GetCurrentProcessId();
	pSession->m_unTid = g_pImports->GetCurrentThreadId();
	if ( !pSession->m_unPid || !pSession->m_unTid )
		return false;

	g_pImports->GetSystemInfo( &pSession->m_SystemInfo );
	if ( pSession->m_SystemInfo.dwPageSize != 4096 )
		return false;

	pSession->m_OsVersion.dwOSVersionInfoSize = sizeof( pSession->m_OsVersion );
	if ( !g_pImports->GetVersionExA( &pSession->m_OsVersion ) )
		return false;

	pSession->m_unPackedVersion =
	    pSession->m_OsVersion.dwPlatformId |
	    ( ( pSession->m_OsVersion.dwMajorVersion | ( pSession->m_OsVersion.dwMinorVersion << 8 ) ) << 8 );

	// @note / sapdragon: 520 chars into 260 char buffers. valve passed the byte size, keep it
	return g_pImports->GetSystemDirectoryW( pSession->m_wszSystemDirectory, 520 ) &&
	       g_pImports->GetWindowsDirectoryW( pSession->m_wszWindowsDirectory, 520 );
}

// @orig: 68 ? ? ? ? BA
void UpdateIntegrityHash() noexcept
{
	// @note / sapdragon: seed is the address of the hash, not its value. valve bug, keep it
	const u32 unSeed = static_cast<u32>( reinterpret_cast<uptr>( &g_unIntegrityHash ) );
	g_unIntegrityHash =
	    crypto::hash::Hash488781ED_t::Of( reinterpret_cast<const u8 *>( &s_Imports ), sizeof( s_Imports ), unSeed );
}

} // namespace

// @orig: 83 3D ? ? ? ? ? 74 ? 51
bool BootstrapMain( const void *pubInput ) noexcept
{
	// @note / sapdragon: the blob lives in .rdata here, so the first call decrypts into a writable copy
	if ( !s_Blob.m_rgub[0] )
		crypto::ice::DecryptBuffer( static_cast<const u8 *>( pubInput ), g_EncryptedBlob.m_rgub,
		                            sizeof( g_EncryptedBlob.m_rgub ), s_Blob.m_rgub );

	s_cResolvedImports = 0;
	s_cLoadedLibraries = 0;
	memset( &s_Imports, 0, sizeof( s_Imports ) );

	const ImportEntry_t *pEntries = k_BlobImage.m_rgEntries;
	const HMODULE hKernel32 = GetModuleHandleA( BlobString( pEntries[0].m_ibLibrary ) );
	g_pImports->LoadLibraryExA = reinterpret_cast<decltype( SystemImports_t::LoadLibraryExA )>(
	    GetProcAddress( hKernel32, BlobString( pEntries[0].m_ibFunction ) ) );
	g_pImports->GetProcAddress = reinterpret_cast<decltype( SystemImports_t::GetProcAddress )>(
	    GetProcAddress( hKernel32, BlobString( pEntries[1].m_ibFunction ) ) );
	g_pSession->m_hNtdll = GetModuleHandleA( BlobString( pEntries[2].m_ibLibrary ) );

	if ( !ResolveAllImports() )
		return false;
	if ( !VerifyCriticalApis() )
		return false;

	g_pSession->m_unLastError = 0;
	if ( !CollectSystemInfo() )
		return false;

	UpdateIntegrityHash();
	return true;
}

// @note / sapdragon: inlined at the end of the workers that tear down, some builds never call it
void BootstrapTeardown() noexcept
{
	for ( u32 iLibrary = 0; iLibrary < s_cLoadedLibraries; ++iLibrary )
	{
		s_Imports.FreeLibrary( s_rghLoadedLibraries[iLibrary] );
		s_rghLoadedLibraries[iLibrary] = nullptr;
	}
	s_cLoadedLibraries = 0;
	memset( &s_Imports, 0, sizeof( s_Imports ) );
	s_cResolvedImports = 0;
}

} // namespace vac::bootstrap
