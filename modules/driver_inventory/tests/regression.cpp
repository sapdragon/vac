// Scripted differential test against the original module.
//
//     driver_inventory_regression.exe [original module.dll]
//
// A live run ends at the first QueryServiceConfigW failure, and on the machine this was written on that is the fifth
// service, so it never reaches the object walk or the string packer. Here both collectors run against the same mocked
// import table.
// Each case compares the status, all 4096 report bytes, and the full sequence of logged API calls.
//
// Without an argument it looks for the DLL in ..\vac-research next to the repository. When the DLL is missing only the
// checks that do not need it run, and the summary says so.
#include "../internal/pe_file.hpp"
#include "../internal/string_table.hpp"
#include "../internal/types.hpp"
#include "bootstrap/blob.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/vac_util.hpp"
#include "util/hashing.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <string>
#include <vector>

using namespace vac;
using namespace vac::workers::driver_inventory;

namespace
{

constexpr u32 k_rvaImports = 0x9D30;
constexpr u32 k_rvaSessionPointer = 0x8000;
constexpr u32 k_rvaCollectDrivers = 0x2D78;
constexpr u32 k_rvaCollectDigests = 0x347D;
constexpr u32 k_rvaPack = 0x6852;
constexpr u32 k_rvaHash = 0x65FA;
constexpr wchar_t k_wszResearchDll[] = L"\\vac-research\\ptr_0x0D0ACF88_crc_2023d8c3\\module.dll";

// The key the bootstrap strings of this build are encrypted with, see internal/module_data.inl.
constexpr u8 k_rgubBootstrapKey[8] = { 0x35, 0xC1, 0x94, 0xED, 0xF3, 0x8D, 0x6A, 0xD4 };

constexpr DWORD k_unVolumeSerial = 0x1234ABCD;
constexpr DWORD k_unOpenByIdError = 0xAB;

u8 *s_pubOriginal = nullptr;
unsigned s_cCases = 0;
unsigned s_cFailures = 0;

void Fail( const std::string &message )
{
	if ( s_cFailures < 40 )
		std::printf( "FAIL: %s\n", message.c_str() );
	++s_cFailures;
}

void Check( bool bOk, const char *pszMessage )
{
	if ( !bOk )
		Fail( pszMessage );
}

std::string Narrow( const wchar_t *pwsz )
{
	if ( !pwsz )
		return "(null)";
	char rgchBuffer[1024]{};
	WideCharToMultiByte( CP_UTF8, 0, pwsz, -1, rgchBuffer, sizeof( rgchBuffer ) - 1, nullptr, nullptr );
	return rgchBuffer;
}

struct Service_t
{
	std::wstring m_Name;
	std::wstring m_Binary;
	std::wstring m_Group = L"Boot";
	std::wstring m_Display = L"Display";
	DWORD m_unOpenError = 0;
	DWORD m_unQueryError = 0;
};

struct Scenario_t
{
	DWORD m_unManagerError = 0;
	DWORD m_unEnumError = 0;
	std::vector<Service_t> m_Services;
	bool m_bDirectoryOpens = true;
	std::vector<std::wstring> m_Objects;

	std::vector<std::wstring> m_Files;
	std::vector<std::wstring> m_MissingPaths;
	DWORD m_unFirstVolumeError = 0;
	std::vector<DWORD> m_VolumeSerials{ 0x11111111, k_unVolumeSerial };
	bool m_bRootOpens = true;
	bool m_bOpenByIdWorks = true;
	bool m_bFileInfoWorks = true;
	bool m_bHasFileInfoImport = true;
	bool m_bHasOpenByIdImport = true;
};

const Scenario_t *s_pScenario = nullptr;
std::vector<std::string> s_Log;
DWORD s_unLastError = 0;
size_t s_iNextFile = 0;
size_t s_iVolume = 0;
HANDLE s_hLastFile = INVALID_HANDLE_VALUE;
const std::wstring *s_pLastFile = nullptr;

void Log( const std::string &line )
{
	s_Log.push_back( line );
}

SC_HANDLE ServiceHandle( size_t iService )
{
	return reinterpret_cast<SC_HANDLE>( 0x1000 + iService );
}

const SC_HANDLE k_hManager = reinterpret_cast<SC_HANDLE>( 0x500 );
const HANDLE k_hRoot = reinterpret_cast<HANDLE>( 0x7700 );
const HANDLE k_hFind = reinterpret_cast<HANDLE>( 0x7800 );
const HANDLE k_hDirectory = reinterpret_cast<HANDLE>( 0x7900 );

DWORD WINAPI MockGetLastError()
{
	return s_unLastError;
}

SC_HANDLE WINAPI MockOpenSCManagerA( LPCSTR pszMachine, LPCSTR pszDatabase, DWORD unAccess )
{
	Log( "OpenSCManagerA " + std::to_string( !pszMachine ) + std::to_string( !pszDatabase ) + " " +
	     std::to_string( unAccess ) );
	if ( s_pScenario->m_unManagerError )
	{
		s_unLastError = s_pScenario->m_unManagerError;
		return nullptr;
	}
	return k_hManager;
}

BOOL WINAPI MockEnumServicesStatusW( SC_HANDLE hManager, DWORD unType, DWORD unState, LPENUM_SERVICE_STATUSW pServices,
                                     DWORD cubBuffer, LPDWORD pcubNeeded, LPDWORD pcReturned, LPDWORD punResume )
{
	Log( "EnumServicesStatusW " + std::to_string( hManager == k_hManager ) + " " + std::to_string( unType ) + " " +
	     std::to_string( unState ) + " " + std::to_string( cubBuffer ) + " " + std::to_string( *punResume ) );
	*pcubNeeded = 0;
	*pcReturned = 0;
	if ( s_pScenario->m_unEnumError && s_pScenario->m_unEnumError != ERROR_MORE_DATA )
	{
		s_unLastError = s_pScenario->m_unEnumError;
		return FALSE;
	}

	for ( size_t iService = 0; iService < s_pScenario->m_Services.size(); ++iService )
	{
		pServices[iService].lpServiceName = const_cast<LPWSTR>( s_pScenario->m_Services[iService].m_Name.c_str() );
		pServices[iService].lpDisplayName = const_cast<LPWSTR>( s_pScenario->m_Services[iService].m_Display.c_str() );
	}
	*pcReturned = static_cast<DWORD>( s_pScenario->m_Services.size() );
	s_unLastError = s_pScenario->m_unEnumError;
	return !s_pScenario->m_unEnumError;
}

SC_HANDLE WINAPI MockOpenServiceW( SC_HANDLE hManager, LPCWSTR pwszName, DWORD unAccess )
{
	Log( "OpenServiceW " + std::to_string( hManager == k_hManager ) + " " + Narrow( pwszName ) + " " +
	     std::to_string( unAccess ) );
	for ( size_t iService = 0; iService < s_pScenario->m_Services.size(); ++iService )
	{
		const Service_t &service = s_pScenario->m_Services[iService];
		if ( service.m_Name.c_str() != pwszName )
			continue;
		if ( service.m_unOpenError )
		{
			s_unLastError = service.m_unOpenError;
			return nullptr;
		}
		return ServiceHandle( iService );
	}
	s_unLastError = ERROR_SERVICE_DOES_NOT_EXIST;
	return nullptr;
}

BOOL WINAPI MockQueryServiceConfigW( SC_HANDLE hService, LPQUERY_SERVICE_CONFIGW pConfig, DWORD cubBuffer,
                                     LPDWORD pcubNeeded )
{
	const size_t iService = reinterpret_cast<size_t>( hService ) - 0x1000;
	Log( "QueryServiceConfigW " + std::to_string( iService ) + " " + std::to_string( cubBuffer ) );
	*pcubNeeded = 0;
	const Service_t &service = s_pScenario->m_Services[iService];
	if ( service.m_unQueryError )
	{
		s_unLastError = service.m_unQueryError;
		return FALSE;
	}

	wchar_t *pwszCursor = reinterpret_cast<wchar_t *>( pConfig + 1 );
	const auto place = [&]( const std::wstring &text )
	{
		wchar_t *pwszStart = pwszCursor;
		std::memcpy( pwszCursor, text.c_str(), ( text.size() + 1 ) * sizeof( wchar_t ) );
		pwszCursor += text.size() + 1;
		return pwszStart;
	};
	pConfig->dwServiceType = 1;
	pConfig->dwStartType = 1;
	pConfig->dwErrorControl = 1;
	pConfig->lpBinaryPathName = place( service.m_Binary );
	pConfig->lpLoadOrderGroup = place( service.m_Group );
	pConfig->dwTagId = 0;
	pConfig->lpDependencies = place( L"" );
	pConfig->lpServiceStartName = place( L"" );
	pConfig->lpDisplayName = place( service.m_Display );
	return TRUE;
}

BOOL WINAPI MockCloseServiceHandle( SC_HANDLE hService )
{
	Log( "CloseServiceHandle " + std::to_string( reinterpret_cast<size_t>( hService ) ) );
	return TRUE;
}

NTSTATUS WINAPI MockNtOpenDirectoryObject( PHANDLE phDirectory, ACCESS_MASK unAccess, POBJECT_ATTRIBUTES pAttributes )
{
	const UNICODE_STRING *pName = pAttributes->ObjectName;
	Log( "NtOpenDirectoryObject " + std::to_string( unAccess ) + " " + std::to_string( pAttributes->Length ) + " " +
	     std::to_string( pAttributes->Attributes ) + " " + std::to_string( pName->Length ) + " " +
	     std::to_string( pName->MaximumLength ) + " " + Narrow( pName->Buffer ) );
	if ( !s_pScenario->m_bDirectoryOpens )
		return static_cast<NTSTATUS>( 0xC0000022 );
	*phDirectory = k_hDirectory;
	return 0;
}

NTSTATUS WINAPI MockNtQueryDirectoryObject( HANDLE hDirectory, void *pBuffer, ULONG cubBuffer, BOOLEAN bSingle,
                                            BOOLEAN bRestart, PULONG punContext, PULONG pcubReturned )
{
	Log( "NtQueryDirectoryObject " + std::to_string( hDirectory == k_hDirectory ) + " " + std::to_string( cubBuffer ) +
	     " " + std::to_string( bSingle ) + " " + std::to_string( bRestart ) + " " + std::to_string( *punContext ) );
	if ( bRestart )
		*punContext = 0;
	if ( *punContext >= s_pScenario->m_Objects.size() )
		return static_cast<NTSTATUS>( 0x8000001A );

	struct Row_t
	{
		UNICODE_STRING m_Name;
		UNICODE_STRING m_Type;
	};
	const std::wstring &name = s_pScenario->m_Objects[*punContext];
	auto *pRow = static_cast<Row_t *>( pBuffer );
	auto *pwszName = reinterpret_cast<wchar_t *>( pRow + 2 );
	std::memcpy( pwszName, name.c_str(), ( name.size() + 1 ) * sizeof( wchar_t ) );
	pRow->m_Name.Length = static_cast<USHORT>( name.size() * sizeof( wchar_t ) );
	pRow->m_Name.MaximumLength = static_cast<USHORT>( pRow->m_Name.Length + sizeof( wchar_t ) );
	pRow->m_Name.Buffer = pwszName;
	pRow->m_Type = {};
	++*punContext;
	*pcubReturned = sizeof( Row_t );
	return 0;
}

HANDLE WINAPI MockCreateFileW( LPCWSTR pwszPath, DWORD unAccess, DWORD unShare, LPSECURITY_ATTRIBUTES,
                               DWORD unDisposition, DWORD unFlags, HANDLE )
{
	Log( "CreateFileW " + Narrow( pwszPath ) + " " + std::to_string( unAccess ) + " " + std::to_string( unShare ) +
	     " " + std::to_string( unDisposition ) + " " + std::to_string( unFlags ) );

	if ( !std::wcsncmp( pwszPath, L"\\\\?\\Volume", 10 ) )
	{
		if ( !s_pScenario->m_bRootOpens )
		{
			s_unLastError = ERROR_ACCESS_DENIED;
			return INVALID_HANDLE_VALUE;
		}
		return k_hRoot;
	}

	for ( const std::wstring &missing : s_pScenario->m_MissingPaths )
	{
		if ( std::wcsstr( pwszPath, missing.c_str() ) )
		{
			s_unLastError = ERROR_FILE_NOT_FOUND;
			return INVALID_HANDLE_VALUE;
		}
	}

	if ( s_pScenario->m_Files.empty() )
	{
		s_unLastError = ERROR_FILE_NOT_FOUND;
		return INVALID_HANDLE_VALUE;
	}

	s_pLastFile = &s_pScenario->m_Files[s_iNextFile++ % s_pScenario->m_Files.size()];
	s_hLastFile =
	    CreateFileW( s_pLastFile->c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
	                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
	return s_hLastFile;
}

BOOL WINAPI MockCloseHandle( HANDLE hHandle )
{
	if ( hHandle == k_hRoot )
	{
		Log( "CloseHandle root" );
		return TRUE;
	}
	Log( "CloseHandle file" );
	return CloseHandle( hHandle );
}

BOOL WINAPI MockGetFileInformationByHandle( HANDLE, LPBY_HANDLE_FILE_INFORMATION pInformation )
{
	Log( "GetFileInformationByHandle" );
	if ( !s_pScenario->m_bFileInfoWorks )
		return FALSE;
	*pInformation = {};
	pInformation->dwVolumeSerialNumber = k_unVolumeSerial;
	pInformation->nFileIndexHigh = 0x11;
	pInformation->nFileIndexLow = static_cast<DWORD>( 0x22 + s_iNextFile );
	return TRUE;
}

HANDLE WINAPI MockFindFirstVolumeW( LPWSTR pwszVolume, DWORD cChars )
{
	Log( "FindFirstVolumeW " + std::to_string( cChars ) );
	if ( s_pScenario->m_unFirstVolumeError )
	{
		s_unLastError = s_pScenario->m_unFirstVolumeError;
		return INVALID_HANDLE_VALUE;
	}
	s_iVolume = 0;
	wcscpy_s( pwszVolume, cChars, L"\\\\?\\Volume{0}\\" );
	return k_hFind;
}

BOOL WINAPI MockFindNextVolumeW( HANDLE, LPWSTR pwszVolume, DWORD cChars )
{
	Log( "FindNextVolumeW " + std::to_string( cChars ) );
	if ( ++s_iVolume >= s_pScenario->m_VolumeSerials.size() )
	{
		s_unLastError = ERROR_NO_MORE_FILES;
		return FALSE;
	}
	wcscpy_s( pwszVolume, cChars, ( L"\\\\?\\Volume{" + std::to_wstring( s_iVolume ) + L"}\\" ).c_str() );
	return TRUE;
}

BOOL WINAPI MockFindVolumeClose( HANDLE )
{
	Log( "FindVolumeClose" );
	return TRUE;
}

BOOL WINAPI MockGetVolumeInformationW( LPCWSTR pwszVolume, LPWSTR, DWORD, LPDWORD punSerial, LPDWORD, LPDWORD, LPWSTR,
                                       DWORD )
{
	Log( "GetVolumeInformationW " + Narrow( pwszVolume ) );
	*punSerial = s_pScenario->m_VolumeSerials[s_iVolume];
	return TRUE;
}

HANDLE WINAPI MockOpenFileById( HANDLE hRoot, LPFILE_ID_DESCRIPTOR pDescriptor, DWORD unAccess, DWORD unShare,
                                LPSECURITY_ATTRIBUTES, DWORD unFlags )
{
	Log( "OpenFileById " + std::to_string( hRoot == k_hRoot ) + " " + std::to_string( pDescriptor->dwSize ) + " " +
	     std::to_string( pDescriptor->Type ) + " " + std::to_string( pDescriptor->FileId.QuadPart ) + " " +
	     std::to_string( unAccess ) + " " + std::to_string( unShare ) + " " + std::to_string( unFlags ) );
	if ( !s_pScenario->m_bOpenByIdWorks || !s_pLastFile )
	{
		s_unLastError = ERROR_ACCESS_DENIED;
		return INVALID_HANDLE_VALUE;
	}
	s_unLastError = k_unOpenByIdError;
	return CreateFileW( s_pLastFile->c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
	                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
}

BOOL WINAPI MockReadFile( HANDLE hFile, LPVOID pBuffer, DWORD cubWanted, LPDWORD pcubRead, LPOVERLAPPED )
{
	const BOOL bResult = ReadFile( hFile, pBuffer, cubWanted, pcubRead, nullptr );
	Log( "ReadFile " + std::to_string( cubWanted ) + " " + std::to_string( *pcubRead ) );
	return bResult;
}

DWORD WINAPI MockSetFilePointer( HANDLE hFile, LONG nOffset, PLONG pnHigh, DWORD unMethod )
{
	Log( "SetFilePointer " + std::to_string( nOffset ) + " " + std::to_string( !pnHigh ) + " " +
	     std::to_string( unMethod ) );
	return SetFilePointer( hFile, nOffset, pnHigh, unMethod );
}

DWORD WINAPI MockGetFileSize( HANDLE hFile, LPDWORD punHigh )
{
	Log( "GetFileSize " + std::to_string( !punHigh ) );
	return GetFileSize( hFile, punHigh );
}

SystemImports_t BuildMockImports( const Scenario_t &scenario )
{
	SystemImports_t imports{};
	imports.GetLastError = MockGetLastError;
	imports.OpenSCManagerA = MockOpenSCManagerA;
	imports.EnumServicesStatusW = MockEnumServicesStatusW;
	imports.OpenServiceW = MockOpenServiceW;
	imports.QueryServiceConfigW = MockQueryServiceConfigW;
	imports.CloseServiceHandle = MockCloseServiceHandle;
	imports.WideCharToMultiByte = WideCharToMultiByte;
	imports.NtOpenDirectoryObject = MockNtOpenDirectoryObject;
	imports.NtQueryDirectoryObject = MockNtQueryDirectoryObject;
	imports.CreateFileW = MockCreateFileW;
	imports.CloseHandle = MockCloseHandle;
	imports.FindFirstVolumeW = MockFindFirstVolumeW;
	imports.FindNextVolumeW = MockFindNextVolumeW;
	imports.FindVolumeClose = MockFindVolumeClose;
	imports.GetVolumeInformationW = MockGetVolumeInformationW;
	imports.ReadFile = MockReadFile;
	imports.SetFilePointer = MockSetFilePointer;
	imports.GetFileSize = MockGetFileSize;
	imports.GetFileInformationByHandle = scenario.m_bHasFileInfoImport ? MockGetFileInformationByHandle : nullptr;
	imports.OpenFileById = scenario.m_bHasOpenByIdImport ? MockOpenFileById : nullptr;
	return imports;
}

void SetDirectories( ModuleSession_t *pSession )
{
	wcscpy_s( pSession->m_wszWindowsDirectory, L"C:\\Windows" );
	wcscpy_s( pSession->m_wszSystemDirectory, L"C:\\Windows\\system32" );
}

struct Run_t
{
	u32 m_unStatus = 0;
	bool m_bCrashed = false;
	std::array<u8, k_cubReport> m_rgubReport{};
	std::vector<std::string> m_Log;
};

using PfnCollect_t = u32 ( * )( void *pReport, const SystemImports_t *pImports );

u32 CollectDriversOurs( void *pReport, const SystemImports_t *pImports )
{
	return static_cast<u32>(
	    CollectDriverServiceInventory( *static_cast<DriverInventoryReport_t *>( pReport ), pImports ) );
}

u32 CollectDigestsOurs( void *pReport, const SystemImports_t *pImports )
{
	return static_cast<u32>( CollectServiceImageDigests( *static_cast<ServiceDigestReport_t *>( pReport ), pImports ) );
}

// The originals are __thiscall with no stack arguments, which fastcall can reach from a free function.
u32 CollectDriversOriginal( void *pReport, const SystemImports_t * )
{
	return reinterpret_cast<u32( __fastcall * )( void *, void * )>( s_pubOriginal + k_rvaCollectDrivers )( pReport,
	                                                                                                       nullptr );
}

u32 CollectDigestsOriginal( void *pReport, const SystemImports_t * )
{
	return reinterpret_cast<u32( __fastcall * )( void *, void * )>( s_pubOriginal + k_rvaCollectDigests )( pReport,
	                                                                                                       nullptr );
}

bool RunGuarded( PfnCollect_t pfnCollect, void *pReport, const SystemImports_t *pImports, u32 *punStatus )
{
	__try
	{
		*punStatus = pfnCollect( pReport, pImports );
		return true;
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		return false;
	}
}

Run_t RunOne( const Scenario_t &scenario, PfnCollect_t pfnCollect, const SystemImports_t &imports )
{
	s_pScenario = &scenario;
	s_Log.clear();
	s_unLastError = 0;
	s_iNextFile = 0;
	s_iVolume = 0;
	s_pLastFile = nullptr;
	s_hLastFile = INVALID_HANDLE_VALUE;

	Run_t run;
	run.m_bCrashed = !RunGuarded( pfnCollect, run.m_rgubReport.data(), &imports, &run.m_unStatus );
	run.m_Log = s_Log;
	return run;
}

std::string DescribeLogDifference( const std::vector<std::string> &original, const std::vector<std::string> &ours )
{
	const size_t cCommon = ( std::min )( original.size(), ours.size() );
	for ( size_t i = 0; i < cCommon; ++i )
	{
		if ( original[i] != ours[i] )
			return "call " + std::to_string( i ) + ": original [" + original[i] + "] ours [" + ours[i] + "]";
	}
	return "call counts " + std::to_string( original.size() ) + "/" + std::to_string( ours.size() );
}

void Compare( const char *pszName, const Scenario_t &scenario, PfnCollect_t pfnOurs, PfnCollect_t pfnOriginal )
{
	++s_cCases;
	if ( !s_pubOriginal )
		return;

	const SystemImports_t imports = BuildMockImports( scenario );
	std::memcpy( s_pubOriginal + k_rvaImports, &imports, sizeof( imports ) );
	SetDirectories( *reinterpret_cast<ModuleSession_t **>( s_pubOriginal + k_rvaSessionPointer ) );
	SetDirectories( g_pSession );

	const Run_t original = RunOne( scenario, pfnOriginal, imports );
	const Run_t ours = RunOne( scenario, pfnOurs, imports );

	if ( original.m_bCrashed != ours.m_bCrashed )
	{
		Fail( std::string( pszName ) + ": crash " + std::to_string( original.m_bCrashed ) + "/" +
		      std::to_string( ours.m_bCrashed ) );
		return;
	}
	if ( original.m_bCrashed )
		return;

	if ( original.m_unStatus != ours.m_unStatus )
		Fail( std::string( pszName ) + ": status " + std::to_string( original.m_unStatus ) + "/" +
		      std::to_string( ours.m_unStatus ) );
	if ( original.m_Log != ours.m_Log )
		Fail( std::string( pszName ) + ": " + DescribeLogDifference( original.m_Log, ours.m_Log ) );
	if ( original.m_rgubReport != ours.m_rgubReport )
	{
		size_t ibFirst = 0;
		while ( original.m_rgubReport[ibFirst] == ours.m_rgubReport[ibFirst] )
			++ibFirst;
		Fail( std::string( pszName ) + ": report differs at " + std::to_string( ibFirst ) );
	}
}

void CompareDrivers( const char *pszName, const Scenario_t &scenario )
{
	Compare( pszName, scenario, CollectDriversOurs, CollectDriversOriginal );
}

void CompareDigests( const char *pszName, const Scenario_t &scenario )
{
	Compare( pszName, scenario, CollectDigestsOurs, CollectDigestsOriginal );
}

std::wstring Numbered( const wchar_t *pwszPrefix, size_t iValue )
{
	return pwszPrefix + std::to_wstring( iValue );
}

std::vector<Service_t> PlainServices( size_t cServices )
{
	std::vector<Service_t> services;
	for ( size_t i = 0; i < cServices; ++i )
		services.push_back(
		    { Numbered( L"Service", i ), L"\\SystemRoot\\System32\\drivers\\" + Numbered( L"file", i ) + L".sys" } );
	return services;
}

void TestDriverInventoryCases()
{
	{
		Scenario_t scenario;
		scenario.m_unManagerError = ERROR_ACCESS_DENIED;
		CompareDrivers( "manager fails", scenario );
	}
	{
		Scenario_t scenario;
		scenario.m_unEnumError = ERROR_INVALID_HANDLE;
		CompareDrivers( "enum fails", scenario );
	}
	{
		Scenario_t scenario;
		scenario.m_unEnumError = ERROR_MORE_DATA;
		scenario.m_Services = PlainServices( 5 );
		CompareDrivers( "enum more data continues", scenario );
	}
	{
		Scenario_t scenario;
		CompareDrivers( "no services no objects", scenario );
	}
	{
		Scenario_t scenario;
		scenario.m_Services = PlainServices( 1 );
		CompareDrivers( "one service", scenario );
	}
	{
		Scenario_t scenario;
		scenario.m_Services = { { L"GroupOnly", L"", L"Filter", L"Some Driver" } };
		CompareDrivers( "empty path uses group format", scenario );
	}
	{
		Scenario_t scenario;
		scenario.m_Services = { { L"NoSlash", L"justafile.sys" } };
		CompareDrivers( "path without backslash", scenario );
	}
	{
		Scenario_t scenario;
		scenario.m_Services = { { L"LeadOnly", L"\\file.sys" } };
		CompareDrivers( "only backslash is the first char", scenario );
	}
	{
		Scenario_t scenario;
		scenario.m_Services = {
		    { L"MpKslDeadBeef", L"\\SystemRoot\\ProgramData\\Defender\\4.18.1\\Drivers\\MpKsl.sys" },
		    { L"mpksl0", L"\\??\\C:\\a\\b.sys" },
		    { L"MPKSL", L"\\??\\c.sys" },
		    { L"MpKsl", L"d.sys" },
		    { L"MpKs", L"\\x\\y\\z.sys" } };
		CompareDrivers( "mpksl prefix strips one folder more", scenario );
	}
	{
		Scenario_t scenario;
		scenario.m_Services = PlainServices( 6 );
		scenario.m_Services[3].m_unOpenError = ERROR_ACCESS_DENIED;
		scenario.m_Objects = { L"Service0", L"Other" };
		CompareDrivers( "open fails midway, no packing", scenario );
	}
	{
		Scenario_t scenario;
		scenario.m_Services = PlainServices( 6 );
		scenario.m_Services[2].m_unQueryError = 1813;
		scenario.m_Objects = { L"Service0" };
		CompareDrivers( "query fails midway keeps handle for cleanup", scenario );
	}
	{
		Scenario_t scenario;
		scenario.m_Services = PlainServices( 400 );
		CompareDrivers( "more services than rows", scenario );
	}
	{
		Scenario_t scenario;
		scenario.m_Services = PlainServices( 4 );
		scenario.m_bDirectoryOpens = false;
		scenario.m_Objects = { L"ignored" };
		CompareDrivers( "directory does not open, still packs", scenario );
	}
	{
		Scenario_t scenario;
		scenario.m_Services = PlainServices( 4 );
		scenario.m_Objects = { L"Service1", L"service2", L"NewObject", L"SERVICE3", L"NewObject", L"Another" };
		CompareDrivers( "objects merge and append", scenario );
	}
	{
		Scenario_t scenario;
		scenario.m_Services = PlainServices( 160 );
		for ( size_t i = 0; i < 40; ++i )
			scenario.m_Objects.push_back( Numbered( L"Object", i ) );
		CompareDrivers( "objects stop at the row limit", scenario );
	}
	{
		Scenario_t scenario;
		for ( size_t i = 0; i < 30; ++i )
			scenario.m_Services.push_back(
			    { Numbered( L"Dup", i ), L"\\SystemRoot\\drivers\\" + Numbered( L"f", i % 4 ) + L".sys" } );
		CompareDrivers( "repeated paths rank first", scenario );
	}
	{
		Scenario_t scenario;
		scenario.m_Services = { { std::wstring( 300, L'L' ), L"\\a\\b.sys" },
		                        { L"Short", std::wstring( 600, L'p' ) + L"\\x.sys" },
		                        { L"Third", L"\\c\\d.sys" } };
		scenario.m_Objects = { std::wstring( 200, L'O' ), std::wstring( 127, L'P' ), std::wstring( 128, L'Q' ) };
		CompareDrivers( "names longer than the buffers", scenario );
	}
	{
		Scenario_t scenario;
		scenario.m_Services = { { L"\u00e9\u00e8\u4e2d\u6587", L"\\SystemRoot\\\u4e2d\u6587\\\u00e9.sys" } };
		scenario.m_Objects = { L"\u00e9\u00e8\u4e2d\u6587", L"\u0416" };
		CompareDrivers( "non ascii", scenario );
	}
	{
		Scenario_t scenario;
		for ( size_t i = 0; i < 169; ++i )
			scenario.m_Services.push_back(
			    { Numbered( L"LongServiceNameForBudget", i ),
			      L"\\SystemRoot\\" + std::wstring( 30 + i % 40, L'd' ) + Numbered( L"\\sub", i ) + L"\\f.sys" } );
		CompareDrivers( "strings do not fit", scenario );
	}
	{
		Scenario_t scenario;
		for ( size_t i = 0; i < 169; ++i )
			scenario.m_Services.push_back(
			    { Numbered( L"Svc", i ), Numbered( L"\\", i ) + std::wstring( 250, L'z' ) + L"\\f.sys" } );
		CompareDrivers( "path text overflows the table", scenario );
	}
	{
		// A hash that is both a name and a path is emitted once.
		Scenario_t scenario;
		scenario.m_Services = {
		    { L"Shared", L"Shared\\file.sys" }, { L"Other", L"Shared\\again.sys" }, { L"Third", L"Other\\x.sys" } };
		CompareDrivers( "hash shared across tables", scenario );
	}

	std::mt19937 random( 0x2023D8C3 );
	for ( int iCase = 0; iCase < 400; ++iCase )
	{
		Scenario_t scenario;
		const size_t cServices = random() % 180;
		for ( size_t i = 0; i < cServices; ++i )
		{
			Service_t service;
			service.m_Name = Numbered( L"Name", random() % 60 ) + Numbered( L"_", i );
			switch ( random() % 8 )
			{
			case 0:
				service.m_Binary = L"";
				break;
			case 1:
				service.m_Binary = Numbered( L"nobackslash", random() % 5 );
				break;
			default:
				service.m_Binary = Numbered( L"\\SystemRoot\\p", random() % 12 ) + L"\\" +
				                   std::wstring( random() % 60, L'x' ) + L"\\f.sys";
				break;
			}
			if ( random() % 400 == 0 )
				service.m_unOpenError = ERROR_ACCESS_DENIED;
			if ( random() % 400 == 0 )
				service.m_unQueryError = 1813;
			scenario.m_Services.push_back( std::move( service ) );
		}
		// Rows live in a block of 32 bytes a service, 16 bytes a row. More new objects than services overflow it, in
		// both versions, so the scenarios stay inside.
		const size_t cObjects = cServices ? random() % (std::min<size_t>)( cServices, 60 ) : 0;
		for ( size_t i = 0; i < cObjects; ++i )
			scenario.m_Objects.push_back( Numbered( L"Name", random() % 90 ) + Numbered( L"_", random() % 40 ) );
		CompareDrivers( ( "random drivers " + std::to_string( iCase ) ).c_str(), scenario );
	}
}

struct PeSection_t
{
	const char *m_pszName;
	u32 m_unVirtualAddress;
	u32 m_cubVirtual;
	u32 m_cubRaw;
	u32 m_ibRaw;
	u32 m_unCharacteristics;
};

struct PeSpec_t
{
	bool m_bPe64 = false;
	u64 m_ulImageBase = 0x10000000;
	u32 m_unAlignment = 0x1000;
	u32 m_cubFile = 0x8000;
	u32 m_ibNtHeaders = 0x80;
	std::vector<PeSection_t> m_Sections;
	IMAGE_DATA_DIRECTORY m_Iat{};
	IMAGE_DATA_DIRECTORY m_Export{};
	IMAGE_DATA_DIRECTORY m_Relocations{};
};

constexpr u32 k_unCode = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
constexpr u32 k_unData = IMAGE_SCN_CNT_INITIALIZED_DATA;

std::vector<u8> BuildPe( const PeSpec_t &spec )
{
	std::vector<u8> image( spec.m_cubFile );
	std::mt19937 random( 1234 + spec.m_cubFile );
	for ( u8 &ubByte : image )
		ubByte = static_cast<u8>( random() );

	auto *pDos = reinterpret_cast<IMAGE_DOS_HEADER *>( image.data() );
	pDos->e_magic = IMAGE_DOS_SIGNATURE;
	pDos->e_lfanew = spec.m_ibNtHeaders;

	u8 *pubNt = image.data() + spec.m_ibNtHeaders;
	*reinterpret_cast<u32 *>( pubNt ) = IMAGE_NT_SIGNATURE;
	auto *pFile = reinterpret_cast<IMAGE_FILE_HEADER *>( pubNt + 4 );
	std::memset( pFile, 0, sizeof( *pFile ) );
	pFile->Machine = spec.m_bPe64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
	pFile->NumberOfSections = static_cast<WORD>( spec.m_Sections.size() );
	pFile->SizeOfOptionalHeader = spec.m_bPe64 ? sizeof( IMAGE_OPTIONAL_HEADER64 ) : sizeof( IMAGE_OPTIONAL_HEADER32 );

	IMAGE_DATA_DIRECTORY *pDirectories;
	if ( spec.m_bPe64 )
	{
		auto *pOptional = reinterpret_cast<IMAGE_OPTIONAL_HEADER64 *>( pFile + 1 );
		std::memset( pOptional, 0, sizeof( *pOptional ) );
		pOptional->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
		pOptional->ImageBase = spec.m_ulImageBase;
		pOptional->SectionAlignment = spec.m_unAlignment;
		pOptional->CheckSum = 0x55667788;
		pDirectories = pOptional->DataDirectory;
	}
	else
	{
		auto *pOptional = reinterpret_cast<IMAGE_OPTIONAL_HEADER32 *>( pFile + 1 );
		std::memset( pOptional, 0, sizeof( *pOptional ) );
		pOptional->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
		pOptional->ImageBase = static_cast<DWORD>( spec.m_ulImageBase );
		pOptional->SectionAlignment = spec.m_unAlignment;
		pOptional->CheckSum = 0x55667788;
		pDirectories = pOptional->DataDirectory;
	}
	pDirectories[IMAGE_DIRECTORY_ENTRY_IAT] = spec.m_Iat;
	pDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT] = spec.m_Export;
	pDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC] = spec.m_Relocations;

	auto *pSections =
	    reinterpret_cast<IMAGE_SECTION_HEADER *>( reinterpret_cast<u8 *>( pFile + 1 ) + pFile->SizeOfOptionalHeader );
	for ( size_t i = 0; i < spec.m_Sections.size(); ++i )
	{
		const PeSection_t &source = spec.m_Sections[i];
		IMAGE_SECTION_HEADER &section = pSections[i];
		std::memset( &section, 0, sizeof( section ) );
		std::memcpy( section.Name, source.m_pszName, (std::min<size_t>)( std::strlen( source.m_pszName ), 8 ) );
		section.VirtualAddress = source.m_unVirtualAddress;
		section.Misc.VirtualSize = source.m_cubVirtual;
		section.SizeOfRawData = source.m_cubRaw;
		section.PointerToRawData = source.m_ibRaw;
		section.Characteristics = source.m_unCharacteristics;
	}
	return image;
}

void PutWord( std::vector<u8> &image, size_t ib, u16 unValue )
{
	std::memcpy( image.data() + ib, &unValue, sizeof( unValue ) );
}

void PutDword( std::vector<u8> &image, size_t ib, u32 unValue )
{
	std::memcpy( image.data() + ib, &unValue, sizeof( unValue ) );
}

// One relocation block at ibBlock, with the given entries.
void PutRelocations( std::vector<u8> &image, size_t ibBlock, u32 unPageRva, const std::vector<u16> &entries )
{
	PutDword( image, ibBlock, unPageRva );
	PutDword( image, ibBlock + 4, static_cast<u32>( 8 + entries.size() * 2 ) );
	for ( size_t i = 0; i < entries.size(); ++i )
		PutWord( image, ibBlock + 8 + i * 2, entries[i] );
}

std::wstring s_TempDirectory;
unsigned s_cTempFiles = 0;

std::wstring WriteTemp( const std::vector<u8> &data )
{
	const std::wstring path = s_TempDirectory + Numbered( L"\\image", s_cTempFiles++ ) + L".bin";
	std::ofstream file( path, std::ios::binary | std::ios::trunc );
	file.write( reinterpret_cast<const char *>( data.data() ), static_cast<std::streamsize>( data.size() ) );
	return path;
}

Scenario_t OneImage( const std::wstring &file )
{
	Scenario_t scenario;
	scenario.m_Services = { { L"Svc", L"\\SystemRoot\\System32\\drivers\\x.sys" } };
	scenario.m_Files = { file };
	return scenario;
}

void CompareImage( const char *pszName, const std::vector<u8> &image )
{
	const std::wstring file = WriteTemp( image );
	CompareDigests( pszName, OneImage( file ) );
	DeleteFileW( file.c_str() );
}

PeSpec_t BasicSpec( bool bPe64 )
{
	PeSpec_t spec;
	spec.m_bPe64 = bPe64;
	spec.m_Sections = { { ".text", 0x1000, 0x2800, 0x2800, 0x400, k_unCode },
	                    { ".rdata", 0x4000, 0x800, 0x800, 0x2C00, k_unData } };
	return spec;
}

size_t OffsetOfFileHeader( const PeSpec_t &spec )
{
	return spec.m_ibNtHeaders + 4;
}

size_t OffsetOfOptional( const PeSpec_t &spec )
{
	return OffsetOfFileHeader( spec ) + sizeof( IMAGE_FILE_HEADER );
}

size_t OffsetOfSections( const PeSpec_t &spec )
{
	return OffsetOfOptional( spec ) +
	       ( spec.m_bPe64 ? sizeof( IMAGE_OPTIONAL_HEADER64 ) : sizeof( IMAGE_OPTIONAL_HEADER32 ) );
}

void TestDigestFlowCases()
{
	const std::wstring image = WriteTemp( BuildPe( BasicSpec( false ) ) );

	{
		Scenario_t scenario;
		scenario.m_unManagerError = ERROR_ACCESS_DENIED;
		CompareDigests( "digest: manager fails", scenario );
	}
	{
		Scenario_t scenario;
		scenario.m_unEnumError = ERROR_INVALID_HANDLE;
		CompareDigests( "digest: enum fails", scenario );
	}
	{
		Scenario_t scenario = OneImage( image );
		scenario.m_unEnumError = ERROR_MORE_DATA;
		CompareDigests( "digest: enum more data", scenario );
	}
	{
		Scenario_t scenario;
		CompareDigests( "digest: no services", scenario );
	}
	{
		Scenario_t scenario = OneImage( image );
		scenario.m_Services = PlainServices( 4 );
		scenario.m_Services[2].m_unOpenError = ERROR_ACCESS_DENIED;
		CompareDigests( "digest: open service fails", scenario );
	}
	{
		Scenario_t scenario = OneImage( image );
		scenario.m_Services = PlainServices( 4 );
		scenario.m_Services[2].m_unQueryError = 1813;
		CompareDigests( "digest: query fails keeps handle for cleanup", scenario );
	}
	{
		Scenario_t scenario = OneImage( image );
		scenario.m_Services = PlainServices( 230 );
		CompareDigests( "digest: stops at the row limit", scenario );
	}
	{
		Scenario_t scenario = OneImage( image );
		scenario.m_Services = PlainServices( 203 );
		CompareDigests( "digest: exactly the row limit", scenario );
	}
	{
		// The failed service leaves its hash in the slot after the last entry.
		Scenario_t scenario = OneImage( image );
		scenario.m_Services = { { L"A", L"\\SystemRoot\\a.sys" },
		                        { L"B", L"\\SystemRoot\\missing.sys" },
		                        { L"C", L"\\SystemRoot\\c.sys" },
		                        { L"LastOneFails", L"\\SystemRoot\\missing2.sys" } };
		scenario.m_MissingPaths = { L"missing" };
		CompareDigests( "digest: last service fails to open", scenario );
	}
	{
		Scenario_t scenario = OneImage( image );
		scenario.m_bFileInfoWorks = false;
		CompareDigests( "digest: file information fails", scenario );
	}
	{
		Scenario_t scenario = OneImage( image );
		scenario.m_bHasFileInfoImport = false;
		CompareDigests( "digest: file information import missing", scenario );
	}
	{
		Scenario_t scenario = OneImage( image );
		scenario.m_bHasOpenByIdImport = false;
		CompareDigests( "digest: open by id import missing", scenario );
	}
	{
		Scenario_t scenario = OneImage( image );
		scenario.m_unFirstVolumeError = ERROR_NO_MORE_FILES;
		CompareDigests( "digest: no volumes", scenario );
	}
	{
		Scenario_t scenario = OneImage( image );
		scenario.m_VolumeSerials = { 1, 2, 3 };
		CompareDigests( "digest: no volume matches", scenario );
	}
	{
		Scenario_t scenario = OneImage( image );
		scenario.m_bRootOpens = false;
		CompareDigests( "digest: root does not open", scenario );
	}
	{
		Scenario_t scenario = OneImage( image );
		scenario.m_bOpenByIdWorks = false;
		CompareDigests( "digest: open by id fails", scenario );
	}
	{
		// The name buffer is 64 bytes here, not 260.
		Scenario_t scenario = OneImage( image );
		scenario.m_Services = { { std::wstring( 63, L'n' ), L"a.sys" },
		                        { std::wstring( 64, L'm' ), L"b.sys" },
		                        { std::wstring( 200, L'o' ), L"c.sys" } };
		CompareDigests( "digest: long service names", scenario );
	}

	const wchar_t *rgpwszPaths[] = { L"\\SystemRoot\\System32\\drivers\\a.sys",
	                                 L"\\systemroot\\system32\\DRIVERS\\a.sys",
	                                 L"\\SYSTEMROOT\\x.sys",
	                                 L"\\??\\C:\\Windows\\System32\\drivers\\a.sys",
	                                 L"\\??\\C:\\plain\\a.sys",
	                                 L"\\\\??\\C:\\a.sys",
	                                 L"\\??\\",
	                                 L"\\??",
	                                 L"System32\\drivers\\a.sys",
	                                 L"system32\\DRIVERS\\a.sys",
	                                 L"drivers\\a.sys",
	                                 L"C:\\foo\\a.sys",
	                                 L"\\SystemDirectory\\a.sys",
	                                 L"\\systemdirectory\\drivers\\a.sys",
	                                 L"\\windows\\a.sys",
	                                 L"\\WINDOWS\\system32\\a.sys",
	                                 L"\\windowsX\\a.sys",
	                                 L"\\SystemRootX\\a.sys",
	                                 L"",
	                                 L"a",
	                                 L"ab",
	                                 L"a:",
	                                 L":a",
	                                 L"system3",
	                                 L"system32",
	                                 L"SySTeM32\\x.sys",
	                                 L"C:\\system32x\\system32\\a.sys",
	                                 L"C:\\sys\\syst\\system32\\a.sys",
	                                 L"ssystem32\\a.sys",
	                                 L"C:\\\u00df\\SYSTEM32\\a.sys",
	                                 L"\"C:\\Program Files\\x.exe\" -arg",
	                                 L"  C:\\spaced.sys",
	                                 L"C:\\a.sys --flag",
	                                 L"\\Device\\HarddiskVolume1\\a.sys" };
	for ( const wchar_t *pwszPath : rgpwszPaths )
	{
		Scenario_t scenario = OneImage( image );
		scenario.m_Services = { { L"Svc", pwszPath } };
		CompareDigests( ( "digest path: " + Narrow( pwszPath ) ).c_str(), scenario );
	}

	{
		// The append is limited to what is left in the buffer, and its terminator lands one past the end.
		// Svc3 stops short of the limit on purpose. Two chars more and system32 -> sysnative pushes the path past the
		// buffer with no terminator. From there both versions read uninitialized stack, so they can not be compared.
		Scenario_t scenario = OneImage( image );
		scenario.m_Services = { { L"Svc", L"\\SystemRoot\\" + std::wstring( 300, L'q' ) },
		                        { L"Svc2", L"\\windows\\" + std::wstring( 244, L'r' ) },
		                        { L"Svc3", L"\\SystemDirectory\\" + std::wstring( 234, L's' ) } };
		CompareDigests( "digest path: append reaches the limit", scenario );
	}
	{
		Scenario_t scenario = OneImage( image );
		scenario.m_Services = { { L"Svc", std::wstring( 200, L't' ) } };
		CompareDigests( "digest path: long relative path", scenario );
	}

	DeleteFileW( image.c_str() );
}

void TestImageShapes()
{
	CompareImage( "image: pe32 plain", BuildPe( BasicSpec( false ) ) );
	CompareImage( "image: pe64 plain", BuildPe( BasicSpec( true ) ) );

	for ( const bool bPe64 : { false, true } )
	{
		const std::string prefix = bPe64 ? "pe64 " : "pe32 ";
		const auto name = [&]( const char *pszCase ) { return "image: " + prefix + pszCase; };

		for ( const u32 cubFile :
		      { 0u,     1u,     63u,     64u,     65u,     207u,    208u,    209u,    0x83u,   0x84u,  0x85u,
		        0x97u,  0x98u,  0x99u,   0x100u,  0x177u,  0x178u,  0x187u,  0x188u,  0x18Cu,  0x1FFu, 0x200u,
		        0x3FFu, 0x400u, 0x1000u, 0x1FFFu, 0x2000u, 0x2001u, 0x2BFFu, 0x2C00u, 0x33FFu, 0x3400u } )
		{
			std::vector<u8> image = BuildPe( BasicSpec( bPe64 ) );
			image.resize( cubFile );
			CompareImage( ( name( "truncated " ) + std::to_string( cubFile ) ).c_str(), image );
		}

		{
			PeSpec_t spec = BasicSpec( bPe64 );
			spec.m_cubFile = 0x3400;
			CompareImage( name( "no overlay" ).c_str(), BuildPe( spec ) );
		}
		{
			std::vector<u8> image = BuildPe( BasicSpec( bPe64 ) );
			image[0] = 'X';
			CompareImage( name( "bad mz" ).c_str(), image );
		}
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			std::vector<u8> image = BuildPe( spec );
			image[spec.m_ibNtHeaders] = 'X';
			CompareImage( name( "bad pe signature" ).c_str(), image );
		}
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			std::vector<u8> image = BuildPe( spec );
			PutWord( image, OffsetOfFileHeader( spec ), IMAGE_FILE_MACHINE_ARM64 );
			CompareImage( name( "bad machine" ).c_str(), image );
		}
		for ( const u16 cSections : { u16( 64 ), u16( 65 ), u16( 0xFFFF ) } )
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			std::vector<u8> image = BuildPe( spec );
			PutWord( image, OffsetOfFileHeader( spec ) + 2, cSections );
			CompareImage( ( name( "section count " ) + std::to_string( cSections ) ).c_str(), image );
		}
		for ( const u16 cubOptional : { u16( 0 ), u16( 100 ), u16( 223 ), u16( 225 ), u16( 239 ), u16( 241 ) } )
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			std::vector<u8> image = BuildPe( spec );
			PutWord( image, OffsetOfFileHeader( spec ) + 16, cubOptional );
			CompareImage( ( name( "optional size " ) + std::to_string( cubOptional ) ).c_str(), image );
		}
		{
			// The magic has to match the size, in both directions.
			PeSpec_t spec = BasicSpec( bPe64 );
			std::vector<u8> image = BuildPe( spec );
			PutWord( image, OffsetOfOptional( spec ),
			         bPe64 ? IMAGE_NT_OPTIONAL_HDR32_MAGIC : IMAGE_NT_OPTIONAL_HDR64_MAGIC );
			CompareImage( name( "optional magic mismatch" ).c_str(), image );
		}
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			spec.m_Sections.clear();
			CompareImage( name( "no sections with overlay" ).c_str(), BuildPe( spec ) );
		}
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			spec.m_Sections.clear();
			spec.m_cubFile = static_cast<u32>( OffsetOfSections( spec ) );
			CompareImage( name( "no sections without overlay" ).c_str(), BuildPe( spec ) );
		}
		{
			// A zero alignment with an overlay is a divide fault in the original. Without one it is never used.
			PeSpec_t spec = BasicSpec( bPe64 );
			spec.m_unAlignment = 0;
			CompareImage( name( "zero alignment with overlay" ).c_str(), BuildPe( spec ) );
			spec.m_cubFile = 0x3400;
			CompareImage( name( "zero alignment without overlay" ).c_str(), BuildPe( spec ) );
		}
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			spec.m_Sections = { { ".rdata", 0x1000, 0x800, 0x800, 0x400, k_unData } };
			CompareImage( name( "no executable section" ).c_str(), BuildPe( spec ) );
		}
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			spec.m_Sections = { { "code1", 0x1000, 0x100, 0x100, 0x400, k_unCode },
			                    { "code2", 0x2000, 0x180, 0x180, 0x600, k_unCode },
			                    { "code3", 0x3000, 0x100, 0x100, 0x800, k_unCode } };
			CompareImage( name( "largest executable wins" ).c_str(), BuildPe( spec ) );
		}
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			spec.m_Sections = { { ".textA", 0x1000, 0x100, 0x100, 0x400, k_unCode },
			                    { "big", 0x2000, 0x900, 0x900, 0x600, k_unCode },
			                    { ".textB", 0x3000, 0x100, 0x100, 0xF00, k_unCode },
			                    { "bigger", 0x4000, 0xA00, 0xA00, 0x1000, k_unCode } };
			CompareImage( name( "last text wins" ).c_str(), BuildPe( spec ) );
		}
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			spec.m_Sections = { { ".text", 0x1000, 0x100, 0x100, 0x400, k_unData },
			                    { "code", 0x2000, 0x100, 0x100, 0x600, k_unCode } };
			CompareImage( name( "text without execute is skipped" ).c_str(), BuildPe( spec ) );
		}
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			spec.m_Sections = { { ".text", 0x1000, 0, 0, 0x400, k_unCode } };
			CompareImage( name( "empty text" ).c_str(), BuildPe( spec ) );
		}
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			spec.m_Sections = { { ".text", 0x1000, 0x800, 0x800, 0, k_unCode } };
			CompareImage( name( "text at file offset zero" ).c_str(), BuildPe( spec ) );
		}
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			spec.m_Sections = { { ".text", 0x1000, 0x20000, 0x20000, 0x400, k_unCode } };
			CompareImage( name( "text past end of file" ).c_str(), BuildPe( spec ) );
		}
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			spec.m_Sections = { { ".text", 0x1000, 0x1000, 0x90000000, 0x400, k_unCode } };
			CompareImage( name( "text size negative as signed" ).c_str(), BuildPe( spec ) );
		}
		for ( const u32 ibRaw : { 0x400u, 0x401u, 0xFFFu, 0x1000u, 0x1001u, 0x1FFFu, 0x2000u, 0x2001u, 0x3000u, 0x7FFFu,
		                          0x8000u, 0x9000u } )
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			spec.m_cubFile = 0x10000;
			spec.m_Sections = { { ".text", 0x1000, 0x5123, 0x5123, ibRaw, k_unCode } };
			CompareImage( ( name( "window at raw offset " ) + std::to_string( ibRaw ) ).c_str(), BuildPe( spec ) );
		}
		for ( const u32 cubRaw : { 1u, 0xFFFu, 0x1000u, 0x1001u, 0x2000u, 0x2001u, 0x3000u, 0x5000u, 0x5001u } )
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			spec.m_cubFile = 0x10000;
			spec.m_Sections = { { ".text", 0x1000, cubRaw, cubRaw, 0x400, k_unCode } };
			CompareImage( ( name( "section size " ) + std::to_string( cubRaw ) ).c_str(), BuildPe( spec ) );
		}
		for ( const u32 ibNtHeaders : { 0x40u, 0x80u, 0xC8u, 0xFFFu, 0x1000u, 0x1FF0u, 0x3000u, 0x7F00u } )
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			spec.m_cubFile = 0x10000;
			spec.m_ibNtHeaders = ibNtHeaders;
			spec.m_Sections = { { ".text", 0x1000, 0x800, 0x800, 0x8000, k_unCode } };
			CompareImage( ( name( "headers at " ) + std::to_string( ibNtHeaders ) ).c_str(), BuildPe( spec ) );
		}
		for ( const u32 ibNtHeaders : { 0xFFFFFFF0u, 0x80000000u, 0x7FFFFFF0u, 0x20000u } )
		{
			PeSpec_t spec = BasicSpec( bPe64 );
			std::vector<u8> image = BuildPe( spec );
			PutDword( image, 0x3C, ibNtHeaders );
			CompareImage( ( name( "e_lfanew " ) + std::to_string( ibNtHeaders ) ).c_str(), image );
		}

		const std::array<IMAGE_DATA_DIRECTORY, 12> rgDirectories = { { { 0x1000, 0x10 },
		                                                               { 0x1800, 0x20 },
		                                                               { 0x1FF8, 0x10 },
		                                                               { 0x2000, 0x1000 },
		                                                               { 0x0FFC, 0x4 },
		                                                               { 0x37F0, 0x100 },
		                                                               { 0, 0 },
		                                                               { 0x5000, 0x10 },
		                                                               { 0xFFFFFFF0, 0x100 },
		                                                               { 0x1000, 0xFFFFFFFF },
		                                                               { 0x1800, 0 },
		                                                               { 0x1800, 0xFFFFFFFC } } };
		for ( size_t iIat = 0; iIat < rgDirectories.size(); ++iIat )
		{
			for ( size_t iExport = 0; iExport < rgDirectories.size(); iExport += 1 + iIat % 3 )
			{
				PeSpec_t spec = BasicSpec( bPe64 );
				spec.m_Iat = rgDirectories[iIat];
				spec.m_Export = rgDirectories[iExport];
				CompareImage(
				    ( name( "directories " ) + std::to_string( iIat ) + "/" + std::to_string( iExport ) ).c_str(),
				    BuildPe( spec ) );
			}
		}
	}

	// Relocations only apply to 32-bit images whose base is not the one Valve hashes against.
	const auto relocated = []( u32 cubRelocations )
	{
		PeSpec_t spec = BasicSpec( false );
		spec.m_ulImageBase = 0x20000000;
		spec.m_Sections.push_back( { ".reloc", 0x5000, 0x400, 0x400, 0x3000, k_unData } );
		spec.m_Relocations = { 0x5000, cubRelocations };
		return spec;
	};
	{
		std::vector<u8> image = BuildPe( relocated( 0x10 ) );
		PutRelocations( image, 0x3000, 0x1000, { 0x3100, 0x3200, 0x3300, 0x0000 } );
		CompareImage( "relocated: plain block", image );
	}
	{
		// A type the original does not know fails the whole hash.
		std::vector<u8> image = BuildPe( relocated( 0x10 ) );
		PutRelocations( image, 0x3000, 0x1000, { 0x3100, 0xA200, 0x3300, 0x0000 } );
		CompareImage( "relocated: unknown type", image );
	}
	{
		// The value crosses the chunk end, patched in the window so the next chunk sees it.
		std::vector<u8> image = BuildPe( relocated( 0x10 ) );
		PutRelocations( image, 0x3000, 0x1000, { 0x3FFE, 0x3FFC, 0x3FFF, 0x0000 } );
		CompareImage( "relocated: value crosses the chunk", image );
	}
	{
		std::vector<u8> image = BuildPe( relocated( 0x2C ) );
		PutRelocations( image, 0x3000, 0x1000, { 0x3010, 0x3020, 0x0000, 0x0000 } );
		PutRelocations( image, 0x3010, 0x2000, { 0x3FFF, 0x3010, 0x0000, 0x0000 } );
		PutRelocations( image, 0x3020, 0x3000, { 0x3010, 0x0000 } );
		CompareImage( "relocated: several blocks over several chunks", image );
	}
	{
		// A block entirely before the section is walked past without patching.
		std::vector<u8> image = BuildPe( relocated( 0x1C ) );
		PutRelocations( image, 0x3000, 0x0000, { 0x3010, 0x3020 } );
		PutRelocations( image, 0x300C, 0x1000, { 0x3010, 0x0000, 0x0000, 0x0000 } );
		CompareImage( "relocated: block before the section", image );
	}
	{
		std::vector<u8> image = BuildPe( relocated( 0x10 ) );
		PutRelocations( image, 0x3000, 0x8000, { 0x3100, 0x3200 } );
		CompareImage( "relocated: block after the section", image );
	}
	CompareImage( "relocated: no relocation directory", BuildPe( relocated( 0 ) ) );
	{
		PeSpec_t spec = relocated( 0x400 );
		spec.m_Relocations = { 0x9000, 0x10 };
		CompareImage( "relocated: directory outside any section", BuildPe( spec ) );
	}
	{
		PeSpec_t spec = relocated( 0x400 );
		spec.m_Sections[2].m_ibRaw = 0x20000;
		CompareImage( "relocated: directory past end of file", BuildPe( spec ) );
	}
	{
		// A lower base wraps the 64-bit delta, only the low half is applied.
		PeSpec_t spec = relocated( 0x10 );
		spec.m_ulImageBase = 0x00400000;
		std::vector<u8> image = BuildPe( spec );
		PutRelocations( image, 0x3000, 0x1000, { 0x3100, 0x3200, 0x0000, 0x0000 } );
		CompareImage( "relocated: base below the hash base", image );
	}
	{
		// 64-bit images load the relocations but never apply them.
		PeSpec_t spec = BasicSpec( true );
		spec.m_ulImageBase = 0x140000000ull;
		spec.m_Sections.push_back( { ".reloc", 0x5000, 0x400, 0x400, 0x3000, k_unData } );
		spec.m_Relocations = { 0x5000, 0x10 };
		std::vector<u8> image = BuildPe( spec );
		PutRelocations( image, 0x3000, 0x1000, { 0x3100, 0xA200, 0x0000, 0x0000 } );
		CompareImage( "pe64: relocations are not applied", image );
	}
}

void TestRealImages()
{
	wchar_t wszWindows[MAX_PATH];
	GetWindowsDirectoryW( wszWindows, MAX_PATH );
	const std::wstring windows = wszWindows;

	const struct
	{
		const wchar_t *m_pwszFolder;
		const wchar_t *m_pwszPattern;
	} rgSources[] = { { L"\\System32\\drivers\\", L"*.sys" }, { L"\\SysWOW64\\", L"*.dll" } };

	for ( const auto &source : rgSources )
	{
		WIN32_FIND_DATAW find;
		// Sysnative is not needed in the regression, the mock picks the file.
		PVOID pvRedirection = nullptr;
		Wow64DisableWow64FsRedirection( &pvRedirection );
		HANDLE hFind = FindFirstFileW( ( windows + source.m_pwszFolder + source.m_pwszPattern ).c_str(), &find );
		unsigned cImages = 0;
		if ( hFind != INVALID_HANDLE_VALUE )
		{
			do
			{
				if ( find.nFileSizeHigh || find.nFileSizeLow > 8 * 1024 * 1024 )
					continue;
				const std::wstring path = windows + source.m_pwszFolder + find.cFileName;
				CompareDigests( ( "real image " + Narrow( path.c_str() ) ).c_str(), OneImage( path ) );
				++cImages;
			} while ( cImages < 60 && FindNextFileW( hFind, &find ) );
			FindClose( hFind );
		}
		Wow64RevertWow64FsRedirection( pvRedirection );
		std::printf( "real images from %ls: %u\n", source.m_pwszFolder, cImages );
	}
}

void TestFuzzedHeaders()
{
	std::mt19937 random( 0xD8C32023 );
	for ( int iCase = 0; iCase < 1500; ++iCase )
	{
		const bool bPe64 = iCase % 2 != 0;
		PeSpec_t spec = BasicSpec( bPe64 );
		std::vector<u8> image = BuildPe( spec );

		// The base stays put: a relocated image with a random directory can spin forever, in both.
		const size_t ibImageBase = OffsetOfOptional( spec ) + ( bPe64 ? 24 : 28 );
		const size_t ibHeaderEnd = OffsetOfSections( spec ) + sizeof( IMAGE_SECTION_HEADER ) * spec.m_Sections.size();
		const int cMutations = 1 + random() % 4;
		for ( int iMutation = 0; iMutation < cMutations; ++iMutation )
		{
			const size_t ib = random() % ibHeaderEnd;
			if ( ib + 8 > ibImageBase && ib < ibImageBase + 8 )
				continue;
			image[ib] = static_cast<u8>( random() % 3 == 0 ? 0 : random() );
		}
		CompareImage( ( "fuzzed header " + std::to_string( iCase ) ).c_str(), image );
	}
}

// What the old suite asserted about section selection, still true without the reference DLL.
void TestSelection()
{
	const auto digest = []( const std::vector<u8> &image )
	{
		std::array<u8, k_cubReport> rgubReport{};
		const std::wstring file = WriteTemp( image );
		const Scenario_t scenario = OneImage( file );
		const SystemImports_t imports = BuildMockImports( scenario );
		SetDirectories( g_pSession );
		s_pScenario = &scenario;
		s_iNextFile = 0;
		s_iVolume = 0;
		CollectDigestsOurs( rgubReport.data(), &imports );
		DeleteFileW( file.c_str() );
		const auto *pReport = reinterpret_cast<const ServiceDigestReport_t *>( rgubReport.data() );
		std::array<u8, 16> rgubDigest{};
		std::memcpy( rgubDigest.data(), pReport->m_rgEntries[0].m_rgubDigest, rgubDigest.size() );
		return rgubDigest;
	};

	PeSpec_t spec;
	spec.m_cubFile = 0xA80;
	spec.m_Sections = { { "code0", 0x1000, 0x100, 0x100, 0x400, k_unCode },
	                    { "code1", 0x2000, 0x180, 0x180, 0x600, k_unCode },
	                    { "code2", 0x3000, 0x100, 0x100, 0x800, k_unCode } };
	std::vector<u8> image = BuildPe( spec );

	const auto before = digest( image );
	Check( before != std::array<u8, 16>{}, "synthetic image hashes" );
	image[0x400] ^= 1;
	Check( digest( image ) == before, "smaller first executable section is not selected" );
	image[0x600] ^= 1;
	Check( digest( image ) != before, "largest executable section is selected" );

	spec.m_Sections[0].m_pszName = ".textA";
	spec.m_Sections[2].m_pszName = ".textB";
	image = BuildPe( spec );
	const auto text = digest( image );
	image[0x400] ^= 1;
	Check( digest( image ) == text, "first text section is superseded" );
	image[0x800] ^= 1;
	Check( digest( image ) != text, "last text section is selected" );

	image = BuildPe( spec );
	const auto overlay = digest( image );
	image[0xA00] ^= 1;
	Check( digest( image ) == overlay, "overlay is not hashed" );
}

void BuildTables( u32 unSeed, StringTable_t &names, StringTable_t &paths, HashVector_t &nameHashes,
                  HashVector_t &pathHashes )
{
	InitStringTable( names );
	InitStringTable( paths );
	nameHashes = {};
	pathHashes = {};

	const u32 cRows = 3 + unSeed % 22;
	for ( u32 iRow = 0; iRow < cRows; ++iRow )
	{
		unSeed = unSeed * 1664525u + 1013904223u;
		char rgchName[32];
		char rgchPath[32];
		std::snprintf( rgchName, sizeof( rgchName ), "name%u", unSeed % 13 );
		std::snprintf( rgchPath, sizeof( rgchPath ), "path%u", ( unSeed >> 8 ) % 9 );
		// Hashes shared across the two tables.
		if ( ( unSeed & 7 ) == 0 )
			std::snprintf( rgchPath, sizeof( rgchPath ), "name1" );

		const i32 cubName = static_cast<i32>( std::strlen( rgchName ) );
		const i32 cubPath = static_cast<i32>( std::strlen( rgchPath ) );
		const u32 unNameHash = util::hashing::PathHashBytes( reinterpret_cast<const u8 *>( rgchName ), cubName );
		const u32 unPathHash = util::hashing::PathHashBytes( reinterpret_cast<const u8 *>( rgchPath ), cubPath );
		AddString( paths, unPathHash, rgchPath, cubPath );
		PushHash( pathHashes, unPathHash );
		AddString( names, unNameHash, rgchName, cubName );
		PushHash( nameHashes, unNameHash );
	}
}

void CallOriginalPack( void *pfnPack, StringTable_t *pNames, StringTable_t *pPaths, HashVector_t *pPathHashes,
                       HashVector_t *pNameHashes, i32 cubBlob, u8 *pubBlob )
{
	// Caller cleaned, with the two tables in ECX and EDX.
	__asm {
		push pubBlob
		push cubBlob
		push pNameHashes
		push pPathHashes
		mov ecx, pPaths
		mov edx, pNames
		call pfnPack
		add esp, 16
	}
}

void TestStringPacker()
{
	for ( u32 unSeed = 0; unSeed < 128; ++unSeed )
	{
		for ( const i32 cubBlob : { 0, 5, 12, 31, 63, 127, 255 } )
		{
			StringTable_t names;
			StringTable_t paths;
			HashVector_t nameHashes;
			HashVector_t pathHashes;
			BuildTables( unSeed, names, paths, nameHashes, pathHashes );
			u8 rgubActual[512]{};
			PackDriverStringTables( names, paths, pathHashes, nameHashes, cubBlob, rgubActual );

			++s_cCases;
			if ( s_pubOriginal )
			{
				StringTable_t originalNames;
				StringTable_t originalPaths;
				HashVector_t originalNameHashes;
				HashVector_t originalPathHashes;
				BuildTables( unSeed, originalNames, originalPaths, originalNameHashes, originalPathHashes );
				u8 rgubExpected[512]{};
				CallOriginalPack( s_pubOriginal + k_rvaPack, &originalNames, &originalPaths, &originalPathHashes,
				                  &originalNameHashes, cubBlob, rgubExpected );

				const size_t cubHashes = sizeof( u32 ) * pathHashes.m_cHashes;
				Check( !std::memcmp( rgubActual, rgubExpected, sizeof( rgubActual ) ), "string packer blob" );
				Check( !std::memcmp( pathHashes.m_punData, originalPathHashes.m_punData, cubHashes ),
				       "string packer path hashes" );
				Check( !std::memcmp( nameHashes.m_punData, originalNameHashes.m_punData, cubHashes ),
				       "string packer name hashes" );

				DestroyStringTable( originalNames );
				DestroyStringTable( originalPaths );
				util::HeapFree( originalNameHashes.m_punData );
				util::HeapFree( originalPathHashes.m_punData );
			}

			DestroyStringTable( names );
			DestroyStringTable( paths );
			util::HeapFree( nameHashes.m_punData );
			util::HeapFree( pathHashes.m_punData );
		}
	}
}

void TestNameHash()
{
	// The original hash gives the seed for empty input, ServiceNameHash gives zero and would be wrong here.
	const u8 ubUnused = 0;
	Check( util::hashing::PathHashBytes( &ubUnused, 0 ) == util::hashing::k_unHashSeed,
	       "empty input hashes to the seed" );
	Check( util::hashing::PathHashBytes( reinterpret_cast<const u8 *>( "MpKslDeadBeef" ), 5 ) == 0xDC8AF399,
	       "mpksl prefix hash" );
	if ( !s_pubOriginal )
		return;

	using PfnHash_t = u32( __fastcall * )( const u8 *, i32 );
	const auto pfnHash = reinterpret_cast<PfnHash_t>( s_pubOriginal + k_rvaHash );
	std::mt19937 random( 7 );
	for ( int iCase = 0; iCase < 512; ++iCase )
	{
		u8 rgubData[64];
		const i32 cubData = random() % 64;
		for ( u8 &ubByte : rgubData )
			ubByte = static_cast<u8>( random() );
		Check( pfnHash( rgubData, cubData ) == util::hashing::PathHashBytes( rgubData, cubData ),
		       "hash matches the original" );
	}
}

void TestBootstrapLifecycle()
{
	u8 rgubInput[k_cubEncryptedConfig]{};
	std::memcpy( rgubInput, k_rgubBootstrapKey, sizeof( k_rgubBootstrapKey ) );
	for ( int i = 0; i < 3; ++i )
	{
		Check( bootstrap::BootstrapMain( rgubInput ), "bootstrap initialization" );
		Check( g_pImports->OpenSCManagerA != nullptr, "imports resolved" );
		bootstrap::BootstrapTeardown();
		bootstrap::BootstrapTeardown();
		Check( g_pImports->OpenSCManagerA == nullptr, "imports cleared after repeated teardown" );
		Check( GetModuleHandleA( "ntdll.dll" ) != nullptr, "borrowed ntdll remains loaded" );
	}
}

std::wstring FindDefaultOriginal()
{
	wchar_t wszExe[MAX_PATH];
	GetModuleFileNameW( nullptr, wszExe, MAX_PATH );
	std::wstring folder = wszExe;
	// <root>\build\tests\x.exe, and vac-research sits next to <root>.
	for ( int i = 0; i < 4 && !folder.empty(); ++i )
		folder.resize( folder.find_last_of( L'\\' ) );
	return folder + k_wszResearchDll;
}

} // namespace

int main( int argc, char **argv )
{
	// A heap fault in a case must not lose what was already printed.
	std::setvbuf( stdout, nullptr, _IONBF, 0 );

	wchar_t wszTemp[MAX_PATH];
	GetTempPathW( MAX_PATH, wszTemp );
	s_TempDirectory = std::wstring( wszTemp ) + L"vac_sdi_regression_" + std::to_wstring( GetCurrentProcessId() );
	CreateDirectoryW( s_TempDirectory.c_str(), nullptr );

	HMODULE hOriginal;
	if ( argc > 1 )
	{
		hOriginal = LoadLibraryA( argv[1] );
		Check( hOriginal != nullptr, "load original module" );
	}
	else
	{
		hOriginal = LoadLibraryW( FindDefaultOriginal().c_str() );
	}
	s_pubOriginal = reinterpret_cast<u8 *>( hOriginal );

	const struct
	{
		const char *m_pszName;
		void ( *m_pfnTest )();
	} rgTests[] = { { "name hash", TestNameHash },
	                { "bootstrap lifecycle", TestBootstrapLifecycle },
	                { "string packer", TestStringPacker },
	                { "section selection", TestSelection },
	                { "driver inventory", TestDriverInventoryCases },
	                { "digest flow", TestDigestFlowCases },
	                { "image shapes", TestImageShapes },
	                { "real images", TestRealImages },
	                { "fuzzed headers", TestFuzzedHeaders } };
	for ( const auto &test : rgTests )
	{
		const unsigned cFailuresBefore = s_cFailures;
		const unsigned cCasesBefore = s_cCases;
		test.m_pfnTest();
		std::printf( "%-20s cases=%u failures=%u\n", test.m_pszName, s_cCases - cCasesBefore,
		             s_cFailures - cFailuresBefore );
	}

	RemoveDirectoryW( s_TempDirectory.c_str() );
	std::printf( "%s: %u cases, %u failures, %s\n", s_cFailures ? "FAIL" : "PASS", s_cCases, s_cFailures,
	             s_pubOriginal ? "compared against the original" : "NO REFERENCE DLL, differential cases skipped" );
	return s_cFailures ? 1 : 0;
}

#include "../internal/module_data.inl"
