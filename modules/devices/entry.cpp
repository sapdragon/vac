// @binary: 40e4df95
#include "internal/types.hpp"
#include "bootstrap/blob.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/module.hpp"
#include "crt/intrinsics.hpp"
#include "util/strings.hpp"
#include "util/win32.hpp"
#include "util/xor_string.hpp"

namespace vac::workers::devices
{

namespace
{

constexpr u8 k_unStringKey = 0x3E;
constexpr char k_szSeparator[] = "\n";

} // namespace

// @orig: 81 EC ? ? ? ? 53
int RunDevices( const Input_t &input, Report_t &report, u32 *pcubOutput ) noexcept
{
	memset( &report, 0, offsetof( Report_t, m_rgDevices ) );
	*pcubOutput = offsetof( Report_t, m_rgDevices );
	report.m_unMagic = k_unReportMagic;

	EScanStatus eStatus = EScanStatus::Ok;
	if ( !bootstrap::BootstrapMain( &input ) )
	{
		eStatus = EScanStatus::BootstrapFailed;
	}
	else
	{
		HDEVINFO hDeviceInfo =
		    g_pImports->SetupDiGetClassDevsA( nullptr, nullptr, nullptr, DIGCF_PRESENT | DIGCF_ALLCLASSES );
		if ( hDeviceInfo == INVALID_HANDLE_VALUE )
		{
			eStatus = static_cast<EScanStatus>( util::GetLastError( g_pImports ) );
		}
		else
		{
			char *pszBuffer =
			    static_cast<char *>( g_pImports->HeapAlloc( g_pImports->GetProcessHeap(), 0, k_cubPropertyBuffer ) );
			if ( pszBuffer == nullptr )
			{
				eStatus = EScanStatus::HeapAllocFailed;
			}
			else
			{
				memset( pszBuffer, 0, k_cubPropertyBuffer );

				SP_DEVINFO_DATA deviceInfo;
				deviceInfo.cbSize = sizeof( deviceInfo );
				for ( DWORD iDevice = 0;; ++iDevice )
				{
					if ( g_pImports->SetupDiEnumDeviceInfo( hDeviceInfo, iDevice, &deviceInfo ) == 0 )
					{
						eStatus = EScanStatus::Ok;
						break;
					}

					DWORD unRegType;
					*pszBuffer = 0;
					if ( g_pImports->SetupDiGetDeviceRegistryPropertyA(
					         hDeviceInfo, &deviceInfo, SPDRP_HARDWAREID, &unRegType,
					         reinterpret_cast<PBYTE>( pszBuffer ), k_cubPropertyLimit, nullptr ) == 0 )
					{
						eStatus = static_cast<EScanStatus>( util::GetLastError( g_pImports ) );
						if ( eStatus != static_cast<EScanStatus>( ERROR_INVALID_DATA ) &&
						     eStatus != static_cast<EScanStatus>( ERROR_INSUFFICIENT_BUFFER ) )
						{
							if ( eStatus != static_cast<EScanStatus>( ERROR_NO_SUCH_DEVINST ) )
								break;
							report.m_eFlags |= EReportFlags::NoSuchDevInst;
						}
					}
					if ( *pszBuffer == 0 )
						continue;

					const u32 cchHardwareIds = util::StrLenA( pszBuffer );
					u32 cchSeparator = util::StrLenA( k_szSeparator );
					if ( cchSeparator > 0xFFFF )
						cchSeparator = 0xFFFF;
					memcpy( &pszBuffer[cchHardwareIds], k_szSeparator, cchSeparator );
					pszBuffer[cchHardwareIds + cchSeparator] = 0;

					const u32 cchBuffered = util::StrLenA( pszBuffer );
					char *pszCompatibleIds = &pszBuffer[cchBuffered];
					unRegType = 0;
					if ( g_pImports->SetupDiGetDeviceRegistryPropertyA(
					         hDeviceInfo, &deviceInfo, SPDRP_COMPATIBLEIDS, &unRegType,
					         reinterpret_cast<PBYTE>( pszCompatibleIds ), k_cubPropertyLimit - cchBuffered,
					         nullptr ) == 0 )
					{
						eStatus = static_cast<EScanStatus>( util::GetLastError( g_pImports ) );
						if ( eStatus != static_cast<EScanStatus>( ERROR_INVALID_DATA ) &&
						     eStatus != static_cast<EScanStatus>( ERROR_INSUFFICIENT_BUFFER ) )
						{
							if ( eStatus != static_cast<EScanStatus>( ERROR_NO_SUCH_DEVINST ) )
								break;
							report.m_eFlags |= EReportFlags::NoSuchDevInst;
						}
					}

					if ( unRegType == REG_MULTI_SZ )
					{
						char *pszEnd = pszCompatibleIds + util::StrLenA( pszCompatibleIds );
						for ( ;; )
						{
							*pszEnd = '\n';
							if ( pszEnd[1] == 0 )
								break;
							pszEnd += util::StrLenA( pszEnd );
						}
					}

					auto szVen = util::MakeXorString<k_unStringKey>( "VEN_" );
					auto szDev = util::MakeXorString<k_unStringKey>( "DEV_" );
					auto szCc = util::MakeXorString<k_unStringKey>( "CC_" );
					szVen.Decode();
					szDev.Decode();
					szCc.Decode();

					u32 unVendor = 0;
					u32 unDevice = 0;
					u32 unCcValue = 0;
					u32 unClass = 0;
					EDeviceKind eKind;
					char *pszVen = FindString( pszBuffer, szVen.Get() );
					char *pszDev = FindString( pszBuffer, szDev.Get() );
					char *pszCc = FindString( pszBuffer, szCc.Get() );
					if ( pszCc != nullptr )
					{
						for ( ;; )
						{
							if ( ParseHex( pszCc + 3, 6, &unCcValue ) == 0 )
							{
								unClass = unCcValue >> 8;
								break;
							}
							pszCc = FindString( pszCc + 3, szCc.Get() );
							if ( pszCc == nullptr )
							{
								unClass = unCcValue;
								break;
							}
						}
					}

					if ( pszVen == nullptr || pszDev == nullptr || ParseHex( pszVen + 4, 4, &unVendor ) != 0 ||
					     ParseHex( pszDev + 4, 4, &unDevice ) != 0 )
					{
						auto szVid = util::MakeXorString<k_unStringKey>( "VID_" );
						auto szPid = util::MakeXorString<k_unStringKey>( "PID_" );
						auto szDevClass = util::MakeXorString<k_unStringKey>( "DevClass_" );
						auto szClass = util::MakeXorString<k_unStringKey>( "\\Class_" );
						auto szSubClass = util::MakeXorString<k_unStringKey>( "SubClass_" );
						auto szProt = util::MakeXorString<k_unStringKey>( "Prot_" );
						szVid.Decode();
						szPid.Decode();
						szDevClass.Decode();
						szClass.Decode();
						szSubClass.Decode();
						szProt.Decode();

						u32 cchDevClass = 9;
						pszVen = FindString( pszBuffer, szVid.Get() );
						pszDev = FindString( pszBuffer, szPid.Get() );
						char *pszDevClass = FindString( pszBuffer, szDevClass.Get() );
						if ( pszDevClass == nullptr )
						{
							pszDevClass = FindString( pszBuffer, szClass.Get() );
							cchDevClass = 7;
						}
						char *pszSubClass = FindString( pszBuffer, szSubClass.Get() );
						char *pszProt = FindString( pszBuffer, szProt.Get() );
						if ( pszVen == nullptr || pszDev == nullptr )
							continue;

						unVendor = 0;
						unDevice = 0;
						u32 unProtocol = 0;
						u32 unSubClass = 0;
						u32 unDevClass = 0;
						if ( ParseHex( pszVen + 4, 4, &unVendor ) != 0 || ParseHex( pszDev + 4, 4, &unDevice ) != 0 )
							continue;

						if ( pszDevClass != nullptr )
							ParseHex( pszDevClass + cchDevClass, 2, &unDevClass );
						if ( pszSubClass != nullptr )
							ParseHex( pszSubClass + 9, 2, &unSubClass );
						if ( pszProt != nullptr )
							ParseHex( pszProt + 5, 2, &unProtocol );

						unClass = static_cast<u8>( unSubClass ) |
						          ( ( static_cast<u8>( unDevClass ) | ( static_cast<u8>( unProtocol ) << 8 ) ) << 8 );
						eKind = EDeviceKind::Usb;
					}
					else
					{
						eKind = EDeviceKind::Pci;
					}

					u32 iEntry = 0;
					for ( ; iEntry < report.m_cDevices; ++iEntry )
					{
						const DeviceEntry_t &entry = report.m_rgDevices[iEntry];
						if ( entry.m_unVendorId == unVendor && entry.m_unDeviceId == unDevice &&
						     static_cast<u16>( unClass ) == static_cast<u16>( entry.m_unKindAndClass >> 8 ) )
							break;
					}
					if ( iEntry != report.m_cDevices )
						continue;

					if ( report.m_cDevices >= ARRAYSIZE( report.m_rgDevices ) )
					{
						eStatus = EScanStatus::TooManyDevices;
						break;
					}

					// @note / sapdragon: the report is only cleared up to the header, so the kind goes in over whatever is there
					DeviceEntry_t &entry = report.m_rgDevices[report.m_cDevices];
					entry.m_unKindAndClass = static_cast<u32>( eKind ) | ( entry.m_unKindAndClass & 0xFFFFFFF0 );
					entry.m_unKindAndClass = ( unClass << 8 ) | static_cast<u8>( entry.m_unKindAndClass );
					entry.m_unVendorId = static_cast<u16>( unVendor );
					entry.m_unDeviceId = static_cast<u16>( unDevice );
					++report.m_cDevices;
				}

				g_pImports->HeapFree( g_pImports->GetProcessHeap(), 0, pszBuffer );
			}
			g_pImports->SetupDiDestroyDeviceInfoList( hDeviceInfo );
		}
	}

	bootstrap::BootstrapTeardown();
	report.m_eStatus = eStatus;
	*pcubOutput = ( 8 * report.m_cDevices + 39 ) & 0xFFFFFFF8;
	return 0;
}

} // namespace vac::workers::devices

#include "internal/module_data.inl"

VAC_WORKER( vac::workers::devices::RunDevices, vac::workers::devices::k_unModuleId, 1, 0xE5, 0x79, 0xC4, 0xEF, 0x20,
            0x0D, 0xC2, 0x92, 0x54, 0x4E, 0xD0, 0x0B, 0xC4, 0x74, 0x1A, 0xEE, 0xE3, 0x3A, 0x11, 0x6C, 0xE3, 0x7D, 0x87,
            0x26, 0x4C, 0xE2, 0x9E, 0xAD, 0xEE, 0x80, 0x4B, 0x0C );
