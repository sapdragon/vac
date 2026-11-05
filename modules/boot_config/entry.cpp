// @binary: 2909d63a
#include "internal/types.hpp"
#include "bootstrap/blob.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/module.hpp"
#include "crt/intrinsics.hpp"
#include "internal/rol3.hpp"
#include "util/win32.hpp"

namespace vac::workers::boot_config
{

namespace
{

using PfnWow64EnableFsRedirection_t = BOOLEAN( WINAPI * )( BOOLEAN );

} // namespace

// @orig: 81 EC ? ? ? ? 53 55 56 57 8B BC 24
int RunBootConfig( const Input_t &input, Report_t &report, u32 *pcubOutput ) noexcept
{
	auto szKernel32 = MakeRol3String( "Kernel32.dll" );
	auto szAdvapi32 = MakeRol3String( "Advapi32.dll" );
	auto szWow64Enable = MakeRol3String( "Wow64EnableWow64FsRedirection" );
	auto szValueName = MakeRol3String( "Element" );
	auto szKeyPath =
	    MakeRol3String( "BCD00000000\\Objects\\{00000000-0000-0000-0000-000000000000}\\Elements\\00000000" );
	static_assert( sizeof( szKeyPath.m_rgChars ) == sizeof( KeyPath_t ) );

	// @note / sapdragon: incoming capacity is ignored, it always writes the whole report
	memset( &report, 0, sizeof( report ) );
	*pcubOutput = sizeof( report );
	report.m_unMagic = k_unReportMagic;
	report.m_unVersion = 2;

	EScanStatus eStatus = EScanStatus::BootstrapFailed;
	if ( bootstrap::BootstrapMain( &input ) )
	{
		szKernel32.Decode();
		const HMODULE hKernel32 = g_pImports->GetModuleHandleA( szKernel32.Get() );
		if ( hKernel32 )
		{
			szAdvapi32.Decode();
			eStatus = EScanStatus::Ok;
			// @note / sapdragon: only kept loaded until the end, nothing is resolved from it
			const HMODULE hAdvapi32 = g_pImports->LoadLibraryExA( szAdvapi32.Get(), nullptr, 0 );

			szWow64Enable.Decode();
			const auto pfnWow64Enable = reinterpret_cast<PfnWow64EnableFsRedirection_t>(
			    g_pImports->GetProcAddress( hKernel32, szWow64Enable.Get() ) );
			u32 unWow64Disabled = 0;
			if ( pfnWow64Enable )
				unWow64Disabled = pfnWow64Enable( FALSE );

			char szSystemDirectory[520];
			if ( g_pImports->GetSystemDirectoryA( szSystemDirectory, sizeof( szSystemDirectory ) ) )
			{
				const wchar_t wszRoot[4] = { static_cast<wchar_t>( szSystemDirectory[0] ), L':', L'\\', 0 };
				g_pImports->GetVolumeInformationW( wszRoot, nullptr, 0,
				                                   reinterpret_cast<LPDWORD>( &report.m_unVolumeSerial ), nullptr,
				                                   nullptr, nullptr, 0 );

				memcpy( szKeyPath.m_rgChars + offsetof( KeyPath_t, m_rgchGuid ), input.m_rgchEncodedGuid,
				        sizeof( input.m_rgchEncodedGuid ) );
				szKeyPath.DecodeAll();
				szValueName.Decode();
				memcpy( report.m_szCurrentGuid, szKeyPath.m_rgChars + offsetof( KeyPath_t, m_rgchGuid ),
				        sizeof( report.m_szCurrentGuid ) );

				ReadElement( szKeyPath.Get(), "12000002", szValueName.Get(), true, &report.m_Element12000002,
				             &report.m_Element12000002.m_unPathHash );
				report.m_unStatus12000002 = report.m_Element12000002.m_ubOpenStatus;
				memcpy( report.m_szValue12000002, report.m_Element12000002.m_szValue,
				        sizeof( report.m_szValue12000002 ) );
				report.m_unFileIndexLow12000002 = report.m_Element12000002.m_unFileIndexLow;
				report.m_unFileIndexHigh12000002 = report.m_Element12000002.m_unFileIndexHigh;

				ReadElement( szKeyPath.Get(), "22000011", szValueName.Get(), true, &report.m_Element22000011, nullptr );
				report.m_unStatus22000011 = report.m_Element22000011.m_ubOpenStatus;
				memcpy( report.m_szValue22000011, report.m_Element22000011.m_szValue,
				        sizeof( report.m_szValue22000011 ) );
				report.m_unFileIndexLow22000011 = report.m_Element22000011.m_unFileIndexLow;
				report.m_unFileIndexHigh22000011 = report.m_Element22000011.m_unFileIndexHigh;

				ReadElement( szKeyPath.Get(), "22000012", szValueName.Get(), true, &report.m_Element22000012, nullptr );
				report.m_unStatus22000012 = report.m_Element22000012.m_ubOpenStatus;
				memcpy( report.m_szValue22000012, report.m_Element22000012.m_szValue,
				        sizeof( report.m_szValue22000012 ) );
				report.m_unFileIndexLow22000012 = report.m_Element22000012.m_unFileIndexLow;
				report.m_unFileIndexHigh22000012 = report.m_Element22000012.m_unFileIndexHigh;

				ReadElement( szKeyPath.Get(), "12000004", szValueName.Get(), false, &report.m_Element12000004,
				             &report.m_Element12000004.m_unDescriptionHash );
				report.m_unStatus12000004 = report.m_Element12000004.m_ubOpenStatus;
				memcpy( report.m_szValue12000004, report.m_Element12000004.m_szValue,
				        sizeof( report.m_szValue12000004 ) );

				HKEY hKey;
				DWORD cubValue;

				memcpy( szKeyPath.m_rgChars + offsetof( KeyPath_t, m_rgchElementId ), "12000030",
				        sizeof( KeyPath_t::m_rgchElementId ) );
				report.m_unStatus12000030 =
				    g_pImports->RegOpenKeyExA( HKEY_LOCAL_MACHINE, szKeyPath.Get(), 0, KEY_QUERY_VALUE, &hKey );
				if ( !report.m_unStatus12000030 )
				{
					// @note / sapdragon: the buffer is never cleared, the copy below takes 32 bytes whatever the value length
					u8 rgubValue[260];
					cubValue = sizeof( rgubValue );
					report.m_unStatus12000030 =
					    g_pImports->RegQueryValueExA( hKey, szValueName.Get(), nullptr, nullptr, rgubValue, &cubValue );
					if ( !report.m_unStatus12000030 )
						memcpy( report.m_szValue12000030, rgubValue, sizeof( report.m_szValue12000030 ) );
					g_pImports->RegCloseKey( hKey );
				}

				memcpy( szKeyPath.m_rgChars + offsetof( KeyPath_t, m_rgchElementId ), "25000020",
				        sizeof( KeyPath_t::m_rgchElementId ) );
				report.m_unStatus25000020 =
				    g_pImports->RegOpenKeyExA( HKEY_LOCAL_MACHINE, szKeyPath.Get(), 0, KEY_QUERY_VALUE, &hKey );
				if ( !report.m_unStatus25000020 )
				{
					cubValue = sizeof( report.m_ulValue25000020 );
					const LSTATUS nStatus = g_pImports->RegQueryValueExA(
					    hKey, szValueName.Get(), nullptr, nullptr,
					    reinterpret_cast<LPBYTE>( &report.m_ulValue25000020 ), &cubValue );
					report.m_unStatus25000020 = nStatus;
					g_pImports->RegCloseKey( hKey );
				}

				memcpy( szKeyPath.m_rgChars + offsetof( KeyPath_t, m_rgchElementId ), "16000049",
				        sizeof( KeyPath_t::m_rgchElementId ) );
				report.m_unStatus16000049 =
				    g_pImports->RegOpenKeyExA( HKEY_LOCAL_MACHINE, szKeyPath.Get(), 0, KEY_QUERY_VALUE, &hKey );
				if ( !report.m_unStatus16000049 )
				{
					cubValue = sizeof( report.m_unValue16000049 );
					const LSTATUS nStatus = g_pImports->RegQueryValueExA(
					    hKey, szValueName.Get(), nullptr, nullptr,
					    reinterpret_cast<LPBYTE>( &report.m_unValue16000049 ), &cubValue );
					report.m_unStatus16000049 = nStatus;
					g_pImports->RegCloseKey( hKey );
				}

				memcpy( szKeyPath.m_rgChars + offsetof( KeyPath_t, m_rgchElementId ), "16000048",
				        sizeof( KeyPath_t::m_rgchElementId ) );
				report.m_unStatus16000048 =
				    g_pImports->RegOpenKeyExA( HKEY_LOCAL_MACHINE, szKeyPath.Get(), 0, KEY_QUERY_VALUE, &hKey );
				if ( !report.m_unStatus16000048 )
				{
					cubValue = sizeof( report.m_unValue16000048 );
					const LSTATUS nStatus = g_pImports->RegQueryValueExA(
					    hKey, szValueName.Get(), nullptr, nullptr,
					    reinterpret_cast<LPBYTE>( &report.m_unValue16000048 ), &cubValue );
					report.m_unStatus16000048 = nStatus;
					g_pImports->RegCloseKey( hKey );
				}

				EnumerateObjects( report, szKeyPath.Get(), szValueName.Get() );
			}
			else
			{
				eStatus = static_cast<EScanStatus>( util::GetLastError( g_pImports ) );
			}

			if ( unWow64Disabled )
				pfnWow64Enable( TRUE );
			if ( hAdvapi32 )
				g_pImports->FreeLibrary( hAdvapi32 );
		}
		else
		{
			eStatus = static_cast<EScanStatus>( util::GetLastError( g_pImports ) );
		}
	}

	bootstrap::BootstrapTeardown();
	report.m_eStatus = eStatus;
	return 0;
}

} // namespace vac::workers::boot_config

#include "internal/module_data.inl"

VAC_WORKER( vac::workers::boot_config::RunBootConfig, vac::workers::boot_config::k_unModuleId, 1, 0x82, 0xAD, 0x6A,
            0xAA, 0xD0, 0x2F, 0x84, 0x86, 0x2C, 0xD4, 0x83, 0xB0, 0x19, 0xB2, 0xC9, 0x0F, 0x4F, 0xF1, 0xA8, 0x75, 0xCE,
            0xF0, 0xFD, 0xD8, 0xCE, 0x6C, 0x1B, 0xF8, 0x60, 0xE5, 0x66, 0xBD );
