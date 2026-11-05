// @binary: a07ed54b
#include "internal/types.hpp"
#include "core/scan_status.hpp"
#include "internal/helpers.hpp"
#include "internal/pe_file_reader.hpp"
#include "internal/process_reader.hpp"
#include "bootstrap/blob.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/module.hpp"
#include "crt/intrinsics.hpp"
#include "nt/nt.hpp"
#include "pe/pe.hpp"
#include "process/process.hpp"
#include "util/encoding.hpp"
#include "util/strings.hpp"
#include "util/xor_string.hpp"

#include <intrin.h>

#pragma intrinsic( _ReturnAddress )

namespace vac::workers::system_info
{

namespace
{

constexpr u8 k_unStringKey = 0x26;

constexpr u32 k_cDirectoryChars = 520;

enum class ESystemInformationClass : u32
{
	TimeOfDay = SystemTimeOfDayInformation,
	Device = 7,
	KernelDebugger = 35,
	RangeStart = 50,
	BootEnvironment = 90,
	CodeIntegrity = SystemCodeIntegrityInformation,
};

enum class EStubMark : u32
{
	MovEdxSharedUserData = 0xFE0300BA,
	CallNext = 1000,
	MovR10Rcx = 0xB8D18B4C,
};

struct SystemTimeOfDay_t
{
	u64 m_ulBootTime;
	u64 m_ulCurrentTime;
	u8 m_rgubRest[32];
};
VAC_LAYOUT_SIZE( SystemTimeOfDay_t, 48 );

struct SystemDevice_t
{
	u32 m_cDisks;
	u32 m_rgunRest[5];
};
VAC_LAYOUT_SIZE( SystemDevice_t, 24 );

struct CodeIntegrity_t
{
	u32 m_cubLength;
	u32 m_unOptions;
};
VAC_LAYOUT_SIZE( CodeIntegrity_t, 8 );

using PfnNtQuerySystemInformation_t = NTSTATUS( WINAPI * )( ESystemInformationClass, void *, ULONG, PULONG );
using PfnGetVersion_t = DWORD( WINAPI * )();
using PfnGetNativeSystemInfo_t = void( WINAPI * )( LPSYSTEM_INFO );
using PfnWow64EnableFsRedirection_t = BOOLEAN( WINAPI * )( BOOLEAN );

// @orig: inlined
u64 ReadSystemTime() noexcept
{
	const volatile nt::KUserSharedData_t &sharedData = nt::GetKUserSharedData();
	u32 unLow;
	i32 nHigh;
	i32 nHigh2;
	do
	{
		nHigh = sharedData.m_SystemTime.m_nHigh1Time;
		unLow = sharedData.m_SystemTime.m_unLowPart;
		nHigh2 = sharedData.m_SystemTime.m_nHigh2Time;
	} while ( nHigh != nHigh2 );
	return ( static_cast<u64>( static_cast<u32>( nHigh ) ) << 32 ) | unLow;
}

// @orig: inlined
u32 ReadTickCountMs() noexcept
{
	const volatile nt::KUserSharedData_t &sharedData = nt::GetKUserSharedData();
	u32 unLow;
	i32 nHigh;
	i32 nHigh2;
	do
	{
		nHigh = sharedData.m_TickCount.m_nHigh1Time;
		unLow = sharedData.m_TickCount.m_unLowPart;
		nHigh2 = sharedData.m_TickCount.m_nHigh2Time;
	} while ( nHigh != nHigh2 );

	if ( static_cast<u32>( nHigh2 ) | unLow )
	{
		const u32 unMultiplier = sharedData.m_unTickCountMultiplier;
		return static_cast<u32>( ( static_cast<u64>( unLow ) * unMultiplier ) >> 24 ) +
		       sharedData.m_unTickCountMultiplier * ( static_cast<u32>( nHigh ) << 8 );
	}
	const u32 unTicks = sharedData.m_unTickCountLowDeprecated;
	return static_cast<u32>( ( static_cast<u64>( unTicks ) * sharedData.m_unTickCountMultiplier ) >> 24 );
}

// @orig: inlined
// @note / sapdragon: the sdk keeps the loaded library list private, so this walks the same imports.inl order. a
// library that failed to load is skipped by both
void CopyBootstrapState( Report_t &report, const SystemImports_t *pImports ) noexcept
{
	const char *rgpszSeen[ARRAYSIZE( report.m_rghLoadedLibraries )];
	u32 cSeen = 0;
	for ( const bootstrap::detail::ImportName_t &importName : bootstrap::detail::k_rgImportNames )
	{
		u32 iSeen = 0;
		while ( iSeen < cSeen && !util::EqualA( rgpszSeen[iSeen], importName.m_szLibrary ) )
			++iSeen;
		if ( iSeen < cSeen )
			continue;

		const HMODULE hLibrary = pImports->GetModuleHandleA( importName.m_szLibrary );
		if ( !hLibrary )
			continue;

		rgpszSeen[cSeen] = importName.m_szLibrary;
		report.m_rghLoadedLibraries[cSeen] = static_cast<u32>( reinterpret_cast<uptr>( hLibrary ) );
		++cSeen;
	}
	report.m_cLoadedLibraries = cSeen;
	report.m_cResolvedImports = ARRAYSIZE( bootstrap::detail::k_rgImportNames );
	memcpy( report.m_rgubImports, pImports, sizeof( report.m_rgubImports ) );
}

} // namespace

// @orig: 55 8B EC B8
int RunSystemInfo( const Input_t &input, Report_t &report, u32 *pcubOutput ) noexcept
{
	auto wszNtdll = util::MakeXorString<k_unStringKey>( L"NtDll.dll" );
	auto szNtdll = util::MakeXorString<k_unStringKey>( "NtDll.dll" );
	auto szKernel32 = util::MakeXorString<k_unStringKey>( "Kernel32.dll" );
	auto szNtQuerySystemInformation = util::MakeXorString<k_unStringKey>( "NtQuerySystemInformation" );
	auto szGetVersion = util::MakeXorString<k_unStringKey>( "GetVersion" );
	auto szGetNativeSystemInfo = util::MakeXorString<k_unStringKey>( "GetNativeSystemInfo" );
	auto szWow64EnableFsRedirection = util::MakeXorString<k_unStringKey>( "Wow64EnableWow64FsRedirection" );
	auto szNtReadVirtualMemory = util::MakeXorString<k_unStringKey>( "NtReadVirtualMemory" );
	auto szNtQueryVirtualMemory = util::MakeXorString<k_unStringKey>( "NtQueryVirtualMemory" );
	auto szNtOpenProcess = util::MakeXorString<k_unStringKey>( "NtOpenProcess" );

	HANDLE hNtdllFile = INVALID_HANDLE_VALUE;
	BOOLEAN bRedirectionWasOn = FALSE;
	CPeFileReader ntdll;

	// @note / sapdragon: incoming capacity is ignored, it always writes the whole report
	memset( &report, 0, sizeof( report ) );
	*pcubOutput = sizeof( report );
	report.m_unMagic = k_unReportMagic;

	EScanStatus eStatus;
	if ( !bootstrap::BootstrapMain( &input ) )
	{
		eStatus = EScanStatus::BootstrapFailed;
	}
	else
	{
		const SystemImports_t *pImports = g_pImports;
		report.m_ulSystemTimeStart = ReadSystemTime();
		report.m_unTickMsStart = ReadTickCountMs();

		wszNtdll.Decode();
		szNtdll.Decode();
		szKernel32.Decode();

		PfnNtQuerySystemInformation_t pfnNtQuerySystemInformation = nullptr;
		PfnGetVersion_t pfnGetVersion = nullptr;
		PfnGetNativeSystemInfo_t pfnGetNativeSystemInfo = nullptr;

		const HMODULE hNtdll = pImports->GetModuleHandleA( szNtdll.Get() );
		const HMODULE hKernel32 = hNtdll ? pImports->GetModuleHandleA( szKernel32.Get() ) : nullptr;
		if ( hKernel32 )
		{
			szNtQuerySystemInformation.Decode();
			szGetVersion.Decode();
			szGetNativeSystemInfo.Decode();
			szWow64EnableFsRedirection.Decode();

			pfnNtQuerySystemInformation = reinterpret_cast<PfnNtQuerySystemInformation_t>(
			    pImports->GetProcAddress( hNtdll, szNtQuerySystemInformation.Get() ) );
			if ( pfnNtQuerySystemInformation )
				pfnGetVersion =
				    reinterpret_cast<PfnGetVersion_t>( pImports->GetProcAddress( hKernel32, szGetVersion.Get() ) );
			if ( pfnGetVersion )
				pfnGetNativeSystemInfo = reinterpret_cast<PfnGetNativeSystemInfo_t>(
				    pImports->GetProcAddress( hKernel32, szGetNativeSystemInfo.Get() ) );
		}

		if ( !pfnGetNativeSystemInfo )
		{
			eStatus = static_cast<EScanStatus>( pImports->GetLastError() );
		}
		else
		{
			const auto pfnWow64EnableFsRedirection = reinterpret_cast<PfnWow64EnableFsRedirection_t>(
			    pImports->GetProcAddress( hKernel32, szWow64EnableFsRedirection.Get() ) );

			report.m_unVersion = pfnGetVersion();

			SYSTEM_INFO systemInfo;
			pfnGetNativeSystemInfo( &systemInfo );
			report.m_unProcessorArchitecture = systemInfo.wProcessorArchitecture;
			report.m_unProcessorType = systemInfo.dwProcessorType;

			// @note / sapdragon: none of these buffers but the boot one are cleared first. a failed query reports
			// whatever was on valve's stack, keep it
			SystemTimeOfDay_t timeOfDay;
			report.m_nTimeOfDayStatus = pfnNtQuerySystemInformation( ESystemInformationClass::TimeOfDay, &timeOfDay,
			                                                         sizeof( timeOfDay ), nullptr );
			report.m_ulCurrentTime = timeOfDay.m_ulCurrentTime;
			report.m_ulBootTime = timeOfDay.m_ulBootTime;

			CodeIntegrity_t codeIntegrity;
			codeIntegrity.m_cubLength = sizeof( codeIntegrity );
			report.m_nCodeIntegrityStatus = pfnNtQuerySystemInformation(
			    ESystemInformationClass::CodeIntegrity, &codeIntegrity, sizeof( codeIntegrity ), nullptr );
			report.m_unCodeIntegrityOptions = codeIntegrity.m_unOptions;

			SystemDevice_t device;
			report.m_nDeviceStatus =
			    pfnNtQuerySystemInformation( ESystemInformationClass::Device, &device, sizeof( device ), nullptr );
			report.m_cDisks = device.m_cDisks;

			u32 unKernelDebugger;
			report.m_nKernelDebuggerStatus =
			    pfnNtQuerySystemInformation( ESystemInformationClass::KernelDebugger, &unKernelDebugger, 2, nullptr );
			report.m_unKernelDebugger = static_cast<u16>( unKernelDebugger );

			u8 rgubBootEnvironment[32];
			memset( rgubBootEnvironment, 0, sizeof( rgubBootEnvironment ) );
			report.m_nBootEnvironmentStatus = pfnNtQuerySystemInformation(
			    ESystemInformationClass::BootEnvironment, rgubBootEnvironment, sizeof( rgubBootEnvironment ), nullptr );
			memcpy( report.m_rgubBootIdentifier, rgubBootEnvironment, sizeof( report.m_rgubBootIdentifier ) );

			i32 nRangeStart;
			report.m_nRangeStartStatus = pfnNtQuerySystemInformation( ESystemInformationClass::RangeStart, &nRangeStart,
			                                                          sizeof( nRangeStart ), nullptr );
			report.m_lRangeStart = nRangeStart;

			report.m_unPid = pImports->GetCurrentProcessId();
			report.m_unTid = pImports->GetCurrentThreadId();

			u32 cchImageName = 0;
			report.m_eImageNameStatus = EScanStatus::NoImageName;
			char szImageName[MAX_PATH + 4];
			if ( pImports->GetProcessImageFileNameA )
				cchImageName =
				    pImports->GetProcessImageFileNameA( pImports->GetCurrentProcess(), szImageName, MAX_PATH );
			if ( cchImageName )
			{
				report.m_eImageNameStatus = EScanStatus::Ok;
				const i32 ibTail =
				    static_cast<i32>( cchImageName ) - static_cast<i32>( sizeof( report.m_rgchImageNameTail ) );
				memcpy( report.m_rgchImageNameTail, &szImageName[ibTail >= 0 ? ibTail : 0],
				        sizeof( report.m_rgchImageNameTail ) );
			}
			else
			{
				report.m_eImageNameStatus = static_cast<EScanStatus>( pImports->GetLastError() );
			}

			wchar_t wszDirectory[k_cDirectoryChars + 2];
			const u32 cchSystemDirectory = pImports->GetSystemDirectoryW( wszDirectory, k_cDirectoryChars );
			if ( !cchSystemDirectory )
			{
				const u32 unError = pImports->GetLastError();
				report.m_eNtdllStatus = static_cast<EScanStatus>( unError );
				report.m_SystemDirectory.m_unError = unError;
			}
			else
			{
				util::encoding::WideToUtf8Bounded( pImports, wszDirectory, report.m_szSystemDirectory,
				                                   sizeof( report.m_szSystemDirectory ) );

				u32 unSerial = 0;
				u64 ulFileId = 0;
				if ( QueryFileIdentity( wszDirectory, &unSerial, &ulFileId, pImports ) )
				{
					report.m_SystemDirectory.m_ulFileId = ulFileId;
					report.m_SystemDirectory.m_unVolumeSerial = unSerial;
				}
				else
				{
					report.m_SystemDirectory.m_unError = pImports->GetLastError();
				}

				wszDirectory[cchSystemDirectory] = L'\\';
				memcpy( &wszDirectory[cchSystemDirectory + 1], wszNtdll.Get(), sizeof( wszNtdll ) );

				if ( pfnWow64EnableFsRedirection )
					bRedirectionWasOn = pfnWow64EnableFsRedirection( FALSE );
				hNtdllFile = pImports->CreateFileW( wszDirectory, GENERIC_READ,
				                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
				                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
				const u32 unOpenError = pImports->GetLastError();
				if ( bRedirectionWasOn )
					pfnWow64EnableFsRedirection( TRUE );

				if ( hNtdllFile == INVALID_HANDLE_VALUE )
				{
					report.m_eNtdllStatus = static_cast<EScanStatus>( unOpenError );
				}
				else
				{
					EScanStatus eReaderStatus = ntdll.Open( hNtdllFile );
					hNtdllFile = INVALID_HANDLE_VALUE;
					if ( eReaderStatus == EScanStatus::Ok )
					{
						report.m_unNtdllTimeDateStamp = ntdll.m_RawFileHeader.TimeDateStamp;
						eReaderStatus = ntdll.ParseExports();
					}

					if ( eReaderStatus != EScanStatus::Ok )
					{
						report.m_eNtdllStatus = eReaderStatus;
					}
					else
					{
						szNtReadVirtualMemory.Decode();
						szNtQueryVirtualMemory.Decode();
						szNtOpenProcess.Decode();

						for ( u32 iName = 0; iName < static_cast<u32>( ntdll.m_cExportNames ); ++iName )
						{
							const char *pszName = ntdll.m_ppszExportNames[iName];
							u32 *punSsn;
							if ( !CompareBounded( pszName, szNtReadVirtualMemory.Get() ) )
								punSsn = &report.m_unSsnNtReadVirtualMemory;
							else if ( !CompareBounded( pszName, szNtQueryVirtualMemory.Get() ) )
								punSsn = &report.m_unSsnNtQueryVirtualMemory;
							else if ( !CompareBounded( pszName, szNtOpenProcess.Get() ) )
								punSsn = &report.m_unSsnNtOpenProcess;
							else if ( !CompareBounded( pszName, szNtQuerySystemInformation.Get() ) )
								punSsn = &report.m_unSsnNtQuerySystemInformation;
							else
								continue;

							const u32 unFunctionRva = ntdll.m_punExportFunctions[iName];
							const IMAGE_SECTION_HEADER *pSection = pe::FindSectionByRva(
							    ntdll.m_pSections, ntdll.m_FileHeader.NumberOfSections, unFunctionRva );
							if ( !pSection )
							{
								report.m_eNtdllStatus = EScanStatus::NoSection;
								continue;
							}

							// @note / sapdragon: 32 bit stubs start with mov eax, so the number is one byte in
							const u32 ibStub = unFunctionRva + pSection->PointerToRawData + ( ntdll.m_bPe64 ? 0 : 1 ) -
							                   pSection->VirtualAddress;
							if ( !ntdll.Seek( ibStub, false ) )
							{
								report.m_eNtdllStatus = EScanStatus::SeekFailed;
								continue;
							}

							u32 rgunStub[2];
							if ( !ntdll.ReadBytes( rgunStub, sizeof( rgunStub ) ) )
							{
								report.m_eNtdllStatus = EScanStatus::ReadFailed;
								continue;
							}

							if ( ntdll.m_bPe64 )
							{
								if ( static_cast<EStubMark>( rgunStub[0] ) == EStubMark::MovR10Rcx )
									*punSsn = rgunStub[1];
								else
									report.m_eNtdllStatus = EScanStatus::UnknownStub;
							}
							else if ( static_cast<EStubMark>( rgunStub[1] ) == EStubMark::MovEdxSharedUserData ||
							          static_cast<EStubMark>( rgunStub[1] ) == EStubMark::CallNext )
							{
								*punSsn = rgunStub[0];
							}
							else
							{
								report.m_eNtdllStatus = EScanStatus::UnknownStub;
							}
						}
					}
				}
			}

			if ( !pImports->GetWindowsDirectoryW( wszDirectory, k_cDirectoryChars ) )
			{
				const u32 unError = pImports->GetLastError();
				report.m_eNtdllStatus = static_cast<EScanStatus>( unError );
				report.m_WindowsDirectory.m_unError = unError;
			}
			else
			{
				util::encoding::WideToUtf8Bounded( pImports, wszDirectory, report.m_szWindowsDirectory,
				                                   sizeof( report.m_szWindowsDirectory ) );

				u32 unSerial = 0;
				u64 ulFileId = 0;
				if ( QueryFileIdentity( wszDirectory, &unSerial, &ulFileId, pImports ) )
				{
					report.m_WindowsDirectory.m_ulFileId = ulFileId;
					report.m_WindowsDirectory.m_unVolumeSerial = unSerial;
				}
				else
				{
					report.m_WindowsDirectory.m_unError = pImports->GetLastError();
				}
			}

			CopyBootstrapState( report, pImports );

			const uptr ulCallerBase = reinterpret_cast<uptr>( _ReturnAddress() ) & 0xFFFF0000u;
			report.m_unCallerBase = static_cast<u32>( ulCallerBase );
			report.m_unCallerDword0 = *reinterpret_cast<const u32 *>( ulCallerBase );
			report.m_unCallerDword114 = *reinterpret_cast<const u32 *>( ulCallerBase + 0x114 );
			report.m_unCallerDword400 = *reinterpret_cast<const u32 *>( ulCallerBase + 0x400 );

			report.m_cVolumes = CollectVolumes( report.m_rgVolumes, pImports );

			report.m_unTargetPid = input.m_unTargetPid;
			if ( report.m_unTargetPid )
			{
				const HANDLE hTarget = pImports->OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, report.m_unTargetPid );
				if ( !hTarget || hTarget == INVALID_HANDLE_VALUE )
				{
					report.m_hTargetProcess = 0;
					report.m_unTargetOpenError = pImports->GetLastError();
				}
				else
				{
					report.m_hTargetProcess = static_cast<u32>( reinterpret_cast<uptr>( hTarget ) );
					report.m_unTargetOpenError = 0;
					report.m_unTargetProcessId = pImports->GetProcessId( hTarget );
					pImports->CloseHandle( hTarget );
				}

				CProcessReader target;
				memset( &target, 0, sizeof( target ) );
				target.m_hProcess = INVALID_HANDLE_VALUE;
				if ( target.ReadProcess( report.m_unTargetPid, EReadFlags::Parameters ) == EScanStatus::Ok )
					util::encoding::WideToUtf8Bounded( pImports, target.m_wszCommandLine, report.m_szTargetCommandLine,
					                                   sizeof( report.m_szTargetCommandLine ) );
				target.Release();
			}

			report.m_ulSystemTimeEnd = ReadSystemTime();
			report.m_unTickMsEnd = ReadTickCountMs();
			eStatus = EScanStatus::Ok;

			if ( hNtdllFile != INVALID_HANDLE_VALUE )
				pImports->CloseHandle( hNtdllFile );
		}
	}

	ntdll.Release();
	bootstrap::BootstrapTeardown();

	report.m_eStatus = eStatus;
	u32 *punReport = reinterpret_cast<u32 *>( &report );
	const u32 unKey = input.m_unReportXorKey;
	for ( u32 iWord = 0; iWord < sizeof( report ) / sizeof( u32 ); ++iWord )
		punReport[iWord] ^= unKey;

	ntdll.Release();
	ntdll.Close();
	return 0;
}

} // namespace vac::workers::system_info

#include "internal/module_data.inl"

VAC_WORKER( vac::workers::system_info::RunSystemInfo, vac::workers::system_info::k_unModuleIdPrimary, 1, 0x7F, 0x02,
            0x99, 0xF9, 0x84, 0x08, 0xE7, 0xB4, 0x25, 0xB1, 0x78, 0x41, 0xC7, 0x20, 0x27, 0xAE, 0x34, 0xEA, 0x5B, 0xB3,
            0xF6, 0xA2, 0xC1, 0xF0, 0x73, 0xC6, 0x2A, 0xB2, 0xE5, 0x6A, 0x3B, 0xD7 );

VAC_WORKER( vac::workers::system_info::RunSystemInfo, vac::workers::system_info::k_unModuleIdSecondary, 1, 0x6F, 0x96,
            0x5B, 0x76, 0xA3, 0xF4, 0x69, 0xCE, 0x44, 0xCD, 0x6F, 0x4E, 0xB1, 0xDE, 0xCF, 0x99, 0xB7, 0x92, 0x87, 0x3E,
            0x90, 0xC7, 0xD8, 0x69, 0x37, 0x61, 0xCF, 0x33, 0x58, 0xE0, 0xE4, 0x43 );
