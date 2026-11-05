// Controlled comparison of system_handles against the original worker.
//
//     system_handles_parity.exe <original module.dll> [--no-frozen] [--fuzz <cases>] [--only <scenario>]
//
// A live run cannot settle this module: processes, handle counts and the clock move between two calls.
// Here both sides run on the same frozen world: the original's bootstrap and teardown are patched to install
// fake imports, the rebuild links against the fake BootstrapMain below. Compared for every case: all report
// bytes plus a sentinel behind them, return value, output size, whether it faulted, and the ordered list of import calls.
//
// Scenario groups: scripted edge cases, seeded random worlds, and "frozen": one real snapshot of this machine taken
// once at start and replayed to both sides, so real paths, handle tables and over 144 record lists are covered too.

#include "../internal/types.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/module.hpp"

#include <algorithm>
#include <array>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <functional>
#include <map>
#include <random>
#include <string>
#include <vector>

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
constinit Module_t *g_pModuleListHead = nullptr;

} // namespace vac

using namespace vac;
using namespace vac::workers::system_handles;

namespace vac::workers::system_handles
{
int RunSystemHandles( const Input_t &input, Report_t &report, u32 *pcubOutput ) noexcept;
}

namespace
{

// Addresses in 1da8fb5c. 9f73e639 has the same code at the same addresses.
constexpr u32 k_rvaWorker = 0x313D;
constexpr u32 k_rvaBootstrapMain = 0x51A3;
constexpr u32 k_rvaBootstrapTeardown = 0x5262;
constexpr u32 k_rvaSessionPointer = 0x6000;
constexpr u32 k_rvaImportsPointer = 0x6004;

const HMODULE k_hFakeNtdll = reinterpret_cast<HMODULE>( 0x7777 );
const HANDLE k_hFakeSnapshot = reinterpret_cast<HANDLE>( 0x5150 );
constexpr u64 k_ulBaseTime = 133000000000000000ull;
constexpr u64 k_ulTicksPerSecond = 10000000ull;
constexpr u32 k_cubSentinel = 64;

using PfnWorker_t = int( __cdecl * )( const void *, void *, u32 * );

struct FakeProcess_t
{
	u32 m_unOpenError = 0;
	bool m_bOpenGivesMinusOne = false;
	bool m_bLimitedDenied = false;
	std::wstring m_wszImage;
	bool m_bNameOverride = false;
	u32 m_unNameResult = 0;
	bool m_bNameWrites = true;
	u32 m_unNameError = 31;
	bool m_bTimesFail = false;
	u32 m_unTimesError = 6;
	u64 m_ulCreate = k_ulBaseTime;
	u64 m_ulExit = 0;
};

struct FakeHandle_t
{
	u32 m_unPidAndBackTrace;
	u8 m_unType;
};

struct SnapshotRow_t
{
	u32 m_unPid;
	u32 m_unParent;
};

struct World_t
{
	std::vector<u32> m_rgunEnum;
	std::vector<SnapshotRow_t> m_rgSnapshot;
	bool m_bSnapshotFails = false;
	std::map<u32, FakeProcess_t> m_Processes;
	std::vector<FakeHandle_t> m_rgHandles;
	u32 m_cMismatches = 0;
	u32 m_unHandleStatus = 0;
	bool m_bNoNtQuery = false;
	int m_iFailAlloc = -1;
	bool m_bDrivesFail = false;
	std::vector<std::pair<wchar_t, std::wstring>> m_rgDrives;
	u32 m_unDefaultOpenError = ERROR_INVALID_PARAMETER;
	u64 m_ulNow = k_ulBaseTime + 5000 * k_ulTicksPerSecond;
	u32 m_unPlatform = VER_PLATFORM_WIN32_NT;
	u32 m_unMajor = 10;
	u32 m_unMinor = 0;
	bool m_bBootFails = false;
};

const World_t *s_pWorld;
std::string s_szTrace;
u32 s_unLastError;
size_t s_iSnapshot;
u32 s_cHandlesOpened;
std::map<HANDLE, u32> s_HandlePids;
int s_cAllocs;
u32 s_cHandleQueries;
u8 *s_pubOriginal;
SystemImports_t *s_pOriginalImports;
ModuleSession_t *s_pOriginalSession;
SystemImports_t s_FakeImports{};

void Trace( const char *pszFormat, ... )
{
	char szLine[160];
	va_list args;
	va_start( args, pszFormat );
	vsnprintf( szLine, sizeof( szLine ), pszFormat, args );
	va_end( args );
	s_szTrace += szLine;
	s_szTrace += '\n';
}

DWORD WINAPI FakeGetLastError()
{
	Trace( "GetLastError -> %u", s_unLastError );
	return s_unLastError;
}

NTSTATUS WINAPI FakeNtQuery( u32 unClass, void *pBuffer, ULONG cubBuffer, ULONG *pcubReturned )
{
	Trace( "NtQuerySystemInformation %u %u %d", unClass, cubBuffer, pcubReturned != nullptr );
	if ( s_cHandleQueries++ < s_pWorld->m_cMismatches )
		return static_cast<NTSTATUS>( 0xC0000004 );
	if ( s_pWorld->m_unHandleStatus )
		return static_cast<NTSTATUS>( s_pWorld->m_unHandleStatus );

	const size_t cHandles = s_pWorld->m_rgHandles.size();
	if ( 4 + cHandles * 16 > cubBuffer )
		return static_cast<NTSTATUS>( 0xC0000004 );

	auto *pubBuffer = static_cast<u8 *>( pBuffer );
	*reinterpret_cast<u32 *>( pubBuffer ) = static_cast<u32>( cHandles );
	for ( size_t iHandle = 0; iHandle < cHandles; ++iHandle )
	{
		u8 *pubEntry = pubBuffer + 4 + iHandle * 16;
		*reinterpret_cast<u32 *>( pubEntry ) = s_pWorld->m_rgHandles[iHandle].m_unPidAndBackTrace;
		pubEntry[4] = s_pWorld->m_rgHandles[iHandle].m_unType;
		pubEntry[5] = 0x5A;
		*reinterpret_cast<u16 *>( pubEntry + 6 ) = static_cast<u16>( iHandle );
		*reinterpret_cast<u32 *>( pubEntry + 8 ) = 0x81000000u + static_cast<u32>( iHandle );
		*reinterpret_cast<u32 *>( pubEntry + 12 ) = 0x1FFFFF;
	}
	return 0;
}

FARPROC WINAPI FakeGetProcAddress( HMODULE hModule, LPCSTR pszName )
{
	Trace( "GetProcAddress %p %s", hModule, pszName );
	if ( s_pWorld->m_bNoNtQuery || std::strcmp( pszName, "NtQuerySystemInformation" ) )
	{
		s_unLastError = ERROR_PROC_NOT_FOUND;
		return nullptr;
	}
	return reinterpret_cast<FARPROC>( FakeNtQuery );
}

BOOL WINAPI FakeEnumProcesses( DWORD *punPids, DWORD cubPids, LPDWORD pcubNeeded )
{
	const DWORD cWrite = min( static_cast<DWORD>( s_pWorld->m_rgunEnum.size() ), cubPids / 4 );
	Trace( "EnumProcesses %u", cubPids );
	if ( cWrite )
		std::memcpy( punPids, s_pWorld->m_rgunEnum.data(), cWrite * 4 );
	*pcubNeeded = cWrite * 4;
	return TRUE;
}

HANDLE WINAPI FakeCreateSnapshot( DWORD unFlags, DWORD unPid )
{
	Trace( "CreateToolhelp32Snapshot %u %u", unFlags, unPid );
	s_iSnapshot = 0;
	if ( s_pWorld->m_bSnapshotFails )
	{
		s_unLastError = ERROR_ACCESS_DENIED;
		return INVALID_HANDLE_VALUE;
	}
	return k_hFakeSnapshot;
}

BOOL FillSnapshotRow( PROCESSENTRY32W *pEntry )
{
	if ( s_iSnapshot >= s_pWorld->m_rgSnapshot.size() )
	{
		s_unLastError = ERROR_NO_MORE_FILES;
		return FALSE;
	}
	pEntry->th32ProcessID = s_pWorld->m_rgSnapshot[s_iSnapshot].m_unPid;
	pEntry->th32ParentProcessID = s_pWorld->m_rgSnapshot[s_iSnapshot].m_unParent;
	++s_iSnapshot;
	return TRUE;
}

BOOL WINAPI FakeProcessFirst( HANDLE hSnapshot, LPPROCESSENTRY32W pEntry )
{
	Trace( "Process32FirstW %p %u", hSnapshot, pEntry->dwSize );
	return FillSnapshotRow( pEntry );
}

BOOL WINAPI FakeProcessNext( HANDLE hSnapshot, LPPROCESSENTRY32W pEntry )
{
	Trace( "Process32NextW %p %u", hSnapshot, pEntry->dwSize );
	return FillSnapshotRow( pEntry );
}

BOOL WINAPI FakeCloseHandle( HANDLE hObject )
{
	Trace( "CloseHandle %p", hObject );
	return TRUE;
}

LPVOID WINAPI FakeVirtualAlloc( LPVOID pAddress, SIZE_T cub, DWORD unType, DWORD unProtect )
{
	Trace( "VirtualAlloc %p %u %x %x", pAddress, static_cast<u32>( cub ), unType, unProtect );
	if ( s_cAllocs++ == s_pWorld->m_iFailAlloc )
	{
		s_unLastError = ERROR_NOT_ENOUGH_MEMORY;
		return nullptr;
	}
	return VirtualAlloc( pAddress, cub, unType, unProtect );
}

BOOL WINAPI FakeVirtualFree( LPVOID pAddress, SIZE_T cub, DWORD unType )
{
	Trace( "VirtualFree %u %x", static_cast<u32>( cub ), unType );
	return VirtualFree( pAddress, cub, unType );
}

HANDLE WINAPI FakeOpenProcess( DWORD unAccess, BOOL bInherit, DWORD unPid )
{
	Trace( "OpenProcess %x %d %u", unAccess, bInherit, unPid );
	const auto iter = s_pWorld->m_Processes.find( unPid );
	if ( iter == s_pWorld->m_Processes.end() )
	{
		s_unLastError = s_pWorld->m_unDefaultOpenError;
		return nullptr;
	}
	const FakeProcess_t &process = iter->second;
	if ( process.m_unOpenError )
	{
		s_unLastError = process.m_unOpenError;
		return process.m_bOpenGivesMinusOne ? INVALID_HANDLE_VALUE : nullptr;
	}
	if ( process.m_bLimitedDenied && unAccess == 0x1000 )
	{
		s_unLastError = ERROR_ACCESS_DENIED;
		return nullptr;
	}
	const HANDLE hProcess = reinterpret_cast<HANDLE>( static_cast<uptr>( 0x40000000u + 4 * ++s_cHandlesOpened ) );
	s_HandlePids[hProcess] = unPid;
	return hProcess;
}

const FakeProcess_t &ProcessOf( HANDLE hProcess )
{
	return s_pWorld->m_Processes.at( s_HandlePids.at( hProcess ) );
}

DWORD WINAPI FakeImageName( HANDLE hProcess, LPWSTR pwszName, DWORD cchName )
{
	const FakeProcess_t &process = ProcessOf( hProcess );
	Trace( "GetProcessImageFileNameW %p %u", hProcess, cchName );
	if ( process.m_bNameWrites )
	{
		const size_t cchCopy = min( process.m_wszImage.size(), static_cast<size_t>( cchName - 1 ) );
		std::wmemcpy( pwszName, process.m_wszImage.data(), cchCopy );
		pwszName[cchCopy] = 0;
	}
	if ( process.m_bNameOverride )
	{
		s_unLastError = process.m_unNameError;
		return process.m_unNameResult;
	}
	return static_cast<DWORD>( min( process.m_wszImage.size(), static_cast<size_t>( cchName - 1 ) ) );
}

BOOL WINAPI FakeProcessTimes( HANDLE hProcess, LPFILETIME pCreate, LPFILETIME pExit, LPFILETIME pKernel,
                              LPFILETIME pUser )
{
	const FakeProcess_t &process = ProcessOf( hProcess );
	Trace( "GetProcessTimes %p", hProcess );
	if ( process.m_bTimesFail )
	{
		s_unLastError = process.m_unTimesError;
		return FALSE;
	}
	std::memcpy( pCreate, &process.m_ulCreate, 8 );
	std::memcpy( pExit, &process.m_ulExit, 8 );
	std::memset( pKernel, 0x11, 8 );
	std::memset( pUser, 0x22, 8 );
	return TRUE;
}

DWORD WINAPI FakeLogicalDrives( DWORD cchBuffer, LPWSTR pwszBuffer )
{
	Trace( "GetLogicalDriveStringsW %u", cchBuffer );
	if ( s_pWorld->m_bDrivesFail )
		return 0;
	wchar_t *pwszWrite = pwszBuffer;
	for ( const auto &drive : s_pWorld->m_rgDrives )
	{
		*pwszWrite++ = drive.first;
		*pwszWrite++ = L':';
		*pwszWrite++ = L'\\';
		*pwszWrite++ = 0;
	}
	*pwszWrite = 0;
	return static_cast<DWORD>( pwszWrite - pwszBuffer );
}

DWORD WINAPI FakeQueryDosDevice( LPCWSTR pwszDrive, LPWSTR pwszDevice, DWORD cchDevice )
{
	Trace( "QueryDosDeviceW %04x %04x %04x %u", pwszDrive[0], pwszDrive[1], pwszDrive[2], cchDevice );
	for ( const auto &drive : s_pWorld->m_rgDrives )
	{
		if ( drive.first == pwszDrive[0] && !drive.second.empty() && drive.second != L"?" )
		{
			std::wcscpy( pwszDevice, drive.second.c_str() );
			return static_cast<DWORD>( drive.second.size() + 2 );
		}
		if ( drive.first == pwszDrive[0] && drive.second.empty() )
		{
			pwszDevice[0] = 0;
			return 1;
		}
	}
	return 0;
}

// Strings stay out of the trace, a failed name query leaves different stack garbage per side.
int WINAPI FakeWideToMulti( UINT unCodePage, DWORD unFlags, LPCWCH pwszIn, int cchIn, LPSTR pszOut, int cubOut,
                            LPCCH pszDefault, LPBOOL pbUsedDefault )
{
	const int nResult =
	    WideCharToMultiByte( unCodePage, unFlags, pwszIn, cchIn, pszOut, cubOut, pszDefault, pbUsedDefault );
	Trace( "WideCharToMultiByte %u %x %d %d %p %p", unCodePage, unFlags, cchIn, cubOut, pszDefault, pbUsedDefault );
	return nResult;
}

void WINAPI FakeSystemTime( LPFILETIME pTime )
{
	Trace( "GetSystemTimeAsFileTime" );
	std::memcpy( pTime, &s_pWorld->m_ulNow, 8 );
}

void FillSession( ModuleSession_t &session )
{
	session.m_OsVersion.dwPlatformId = s_pWorld->m_unPlatform;
	session.m_OsVersion.dwMajorVersion = s_pWorld->m_unMajor;
	session.m_OsVersion.dwMinorVersion = s_pWorld->m_unMinor;
	session.m_unPackedVersion =
	    s_pWorld->m_unPlatform | ( ( s_pWorld->m_unMajor | ( s_pWorld->m_unMinor << 8 ) ) << 8 );
	session.m_hNtdll = k_hFakeNtdll;
}

bool __fastcall FakeOriginalBootstrap( const void * )
{
	Trace( "BootstrapMain" );
	if ( s_pWorld->m_bBootFails )
		return false;
	*s_pOriginalImports = s_FakeImports;
	FillSession( *s_pOriginalSession );
	return true;
}

void __cdecl FakeOriginalTeardown()
{
	Trace( "BootstrapTeardown" );
	std::memset( s_pOriginalImports, 0, sizeof( *s_pOriginalImports ) );
}

void Patch( void *pWhere, const void *pfnTarget )
{
	DWORD unOld;
	VirtualProtect( pWhere, 5, PAGE_EXECUTE_READWRITE, &unOld );
	auto *pubCode = static_cast<u8 *>( pWhere );
	pubCode[0] = 0xE9;
	*reinterpret_cast<i32 *>( pubCode + 1 ) = static_cast<i32>( static_cast<const u8 *>( pfnTarget ) - pubCode - 5 );
	FlushInstructionCache( GetCurrentProcess(), pWhere, 5 );
	VirtualProtect( pWhere, 5, unOld, &unOld );
}

struct Outcome_t
{
	int m_nResult = 0;
	u32 m_cubOutput = 0;
	DWORD m_unFault = 0;
	std::array<u8, k_cubReport + k_cubSentinel> m_rgubReport{};
	std::string m_szTrace;
};

int RunOriginalGuarded( const Input_t *pInput, u8 *pubReport, u32 *pcubOutput, DWORD *punFault )
{
	__try
	{
		return reinterpret_cast<PfnWorker_t>( s_pubOriginal + k_rvaWorker )( pInput, pubReport, pcubOutput );
	}
	__except ( *punFault = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER )
	{
		return -1;
	}
}

int RunRebuildGuarded( const Input_t *pInput, u8 *pubReport, u32 *pcubOutput, DWORD *punFault )
{
	__try
	{
		return RunSystemHandles( *pInput, *reinterpret_cast<Report_t *>( pubReport ), pcubOutput );
	}
	__except ( *punFault = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER )
	{
		return -1;
	}
}

// The scan context is not cleared and the first pass reads its clock before it is set, so that field is whatever the
// stack held. Painting gives both sides the same garbage, and running with two values covers both branches it can take.
__declspec( noinline ) void PaintStack( u32 unValue )
{
	volatile u32 rgunStack[0x10000 / sizeof( u32 )];
	for ( u32 iValue = 0; iValue < sizeof( rgunStack ) / sizeof( rgunStack[0] ); ++iValue )
		rgunStack[iValue] = unValue;
}

void RunSide( bool bOriginal, const World_t &world, const Input_t &input, u32 cubCapacity, u32 unPaint,
              Outcome_t &outcome )
{
	s_pWorld = &world;
	s_szTrace.clear();
	s_unLastError = 77;
	s_iSnapshot = 0;
	s_cHandlesOpened = 0;
	s_HandlePids.clear();
	s_cAllocs = 0;
	s_cHandleQueries = 0;

	outcome.m_rgubReport.fill( 0xCD );
	outcome.m_cubOutput = cubCapacity;
	outcome.m_unFault = 0;
	PaintStack( unPaint );
	outcome.m_nResult =
	    bOriginal ? RunOriginalGuarded( &input, outcome.m_rgubReport.data(), &outcome.m_cubOutput, &outcome.m_unFault )
	              : RunRebuildGuarded( &input, outcome.m_rgubReport.data(), &outcome.m_cubOutput, &outcome.m_unFault );
	outcome.m_szTrace = s_szTrace;
}

u32 s_cCases;
u32 s_cFailures;
u32 s_cFaulted;

void PrintTraceDifference( const std::string &szA, const std::string &szB )
{
	size_t ib = 0;
	while ( ib < szA.size() && ib < szB.size() && szA[ib] == szB[ib] )
		++ib;
	const size_t ibLine = szA.rfind( '\n', ib ) == std::string::npos ? 0 : szA.rfind( '\n', ib ) + 1;
	std::printf( "  trace differs at byte %u:\n  original: %.200s\n  rebuild:  %.200s\n", static_cast<u32>( ib ),
	             szA.substr( ibLine, 120 ).c_str(), szB.size() > ibLine ? szB.substr( ibLine, 120 ).c_str() : "" );
}

bool CompareCase( const char *pszName, const World_t &world, const Input_t &input, u32 cubCapacity, u32 unPaint )
{
	static Outcome_t expected;
	static Outcome_t actual;
	RunSide( true, world, input, cubCapacity, unPaint, expected );
	RunSide( false, world, input, cubCapacity, unPaint, actual );

	++s_cCases;
	s_cFaulted += expected.m_unFault != 0;
	const bool bEqual = expected.m_nResult == actual.m_nResult && expected.m_cubOutput == actual.m_cubOutput &&
	                    expected.m_unFault == actual.m_unFault && expected.m_rgubReport == actual.m_rgubReport &&
	                    expected.m_szTrace == actual.m_szTrace;
	if ( bEqual )
		return true;

	++s_cFailures;
	if ( s_cFailures <= 12 )
	{
		std::printf( "DIFF %s paint=%x min=%u max=%u age=%u flags=%x cap=%u ret=%d/%d size=%u/%u fault=%lx/%lx\n",
		             pszName, unPaint, input.m_unMinPid, input.m_unMaxPid, input.m_unMaxAgeSeconds,
		             static_cast<u32>( input.m_eFlags ), cubCapacity, expected.m_nResult, actual.m_nResult,
		             expected.m_cubOutput, actual.m_cubOutput, expected.m_unFault, actual.m_unFault );
		u32 cShown = 0;
		for ( u32 ib = 0; ib < expected.m_rgubReport.size() && cShown < 12; ++ib )
		{
			if ( expected.m_rgubReport[ib] != actual.m_rgubReport[ib] )
			{
				std::printf( "  +0x%03x %02x/%02x\n", ib, expected.m_rgubReport[ib], actual.m_rgubReport[ib] );
				++cShown;
			}
		}
		if ( expected.m_szTrace != actual.m_szTrace )
			PrintTraceDifference( expected.m_szTrace, actual.m_szTrace );
	}
	return false;
}

Input_t MakeInput( u32 unMinPid, u32 unMaxPid, u32 unMaxAge, u32 unFlags )
{
	Input_t input{};
	for ( u32 ib = 0; ib < sizeof( input.m_rgubBootstrap ); ++ib )
		input.m_rgubBootstrap[ib] = static_cast<u8>( 0x31 * ib + 7 );
	for ( u32 ib = 0; ib < sizeof( input.m_rgubReserved ); ++ib )
		input.m_rgubReserved[ib] = static_cast<u8>( 0x17 * ib + 3 );
	input.m_unMinPid = unMinPid;
	input.m_unMaxPid = unMaxPid;
	input.m_unMaxAgeSeconds = unMaxAge;
	// Only the low 3 bits are flags, the rest is filler in captured packets.
	input.m_eFlags = static_cast<EInputFlags>( 0x9104E640u | unFlags );
	return input;
}

void ComparePainted( const char *pszName, const World_t &world, const Input_t &input, u32 cubCapacity )
{
	CompareCase( pszName, world, input, cubCapacity, 0 );
	CompareCase( pszName, world, input, cubCapacity, 0xCCCCCCCC );
}

void CompareAllInputs( const char *pszName, const World_t &world )
{
	struct Range_t
	{
		u32 m_unMin;
		u32 m_unMax;
	};
	static constexpr Range_t k_rgRanges[] = { { 0, 0 }, { 8, 0 }, { 0, 400 }, { 200, 600 }, { 0xFFFFFFF0, 0 } };
	static constexpr u32 k_rgunAges[] = { 0, 1200, 0xFFFFFFFF };
	for ( u32 unFlags = 0; unFlags < 8; ++unFlags )
	{
		for ( const Range_t &range : k_rgRanges )
		{
			for ( const u32 unAge : k_rgunAges )
				ComparePainted( pszName, world, MakeInput( range.m_unMin, range.m_unMax, unAge, unFlags ),
				                k_cubReport );
		}
	}
}

void AddProcess( World_t &world, u32 unPid, u32 unParent, const std::wstring &wszImage, u64 ulCreate = k_ulBaseTime,
                 u64 ulExit = 0 )
{
	world.m_rgunEnum.push_back( unPid );
	world.m_rgSnapshot.push_back( { unPid, unParent } );
	FakeProcess_t process;
	process.m_wszImage = wszImage;
	process.m_ulCreate = ulCreate;
	process.m_ulExit = ulExit;
	world.m_Processes[unPid] = process;
}

World_t BaseWorld()
{
	World_t world;
	world.m_rgDrives = { { L'A', L"" },
	                     { L'B', L"?" },
	                     { L'C', L"\\Device\\HarddiskVolume3" },
	                     { L'D', L"\\Device\\HarddiskVolume10" } };
	AddProcess( world, 0, 0, L"" );
	world.m_Processes.erase( 0 );
	AddProcess( world, 4, 0, L"\\Device\\HarddiskVolume3\\Windows\\System32\\ntoskrnl.exe" );
	AddProcess( world, 100, 4, L"\\Device\\HarddiskVolume3\\Windows\\System32\\smss.exe" );
	AddProcess( world, 204, 100, L"\\device\\harddiskvolume3\\WINDOWS\\system32\\CSRSS.exe" );
	AddProcess( world, 308, 100, L"\\Device\\HarddiskVolume10\\Games\\game.exe" );
	AddProcess( world, 412, 308, L"\\Device\\HarddiskVolume7\\Tools\\tool.exe" );
	AddProcess( world, 516, 308, L"\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe" );
	AddProcess( world, 620, 308, L"\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe" );
	for ( const u32 unPid : { 4u, 100u, 204u, 308u, 412u, 516u, 620u } )
	{
		for ( const u8 unType : { 0, 7, 31, 32, 37, 54, 55, 63, 64, 200, 255 } )
			world.m_rgHandles.push_back( { unPid, static_cast<u8>( unType ) } );
	}
	return world;
}

void RunScripted( const char *pszOnly )
{
	using Builder_t = std::function<void( World_t & )>;
	const std::pair<const char *, Builder_t> rgScenarios[] = {
	    { "base", []( World_t & ) {} },
	    { "empty_system", []( World_t &world ) { world = World_t{}; } },
	    { "no_snapshot_rows_enum_only", []( World_t &world ) { world.m_rgSnapshot.clear(); } },
	    { "unsorted_snapshot",
	      []( World_t &world )
	      {
		      std::swap( world.m_rgSnapshot[0], world.m_rgSnapshot[5] );
		      std::swap( world.m_rgSnapshot[1], world.m_rgSnapshot[7] );
	      } },
	    { "duplicate_pid_in_snapshot", []( World_t &world ) { world.m_rgSnapshot.push_back( { 308, 999 } ); } },
	    { "pid_not_multiple_of_4_below_the_top",
	      []( World_t &world ) { AddProcess( world, 310, 4, L"\\Device\\HarddiskVolume3\\odd\\odd.exe" ); } },
	    { "gap_pid_alive_only_by_brute_force",
	      []( World_t &world )
	      {
		      FakeProcess_t hidden;
		      hidden.m_wszImage = L"\\Device\\HarddiskVolume3\\Hidden\\hidden.exe";
		      world.m_Processes[300] = hidden;
		      FakeProcess_t denied;
		      denied.m_unOpenError = ERROR_ACCESS_DENIED;
		      world.m_Processes[304] = denied;
	      } },
	    { "handle_only_pids",
	      []( World_t &world )
	      {
		      FakeProcess_t hidden;
		      hidden.m_wszImage = L"\\Device\\HarddiskVolume3\\Hidden\\hidden.exe";
		      world.m_Processes[2000] = hidden;
		      world.m_rgHandles.push_back( { 2000, 3 } );
		      world.m_rgHandles.push_back( { 3000, 33 } );
		      world.m_rgHandles.push_back( { 2000, 40 } );
		      world.m_rgHandles.push_back( { 3000, 3 } );
		      world.m_rgHandles.push_back( { 4, 9 } );
	      } },
	    { "backtrace_bits_in_pid",
	      []( World_t &world )
	      {
		      world.m_rgHandles.push_back( { 0x00010000u | 308, 3 } );
		      world.m_rgHandles.push_back( { 0x00020000u | 4, 4 } );
	      } },
	    { "handle_count_saturates",
	      []( World_t &world )
	      {
		      for ( u32 iHandle = 0; iHandle < 300; ++iHandle )
			      world.m_rgHandles.push_back( { 308, static_cast<u8>( iHandle % 60 ) } );
		      for ( u32 iHandle = 0; iHandle < 254; ++iHandle )
			      world.m_rgHandles.push_back( { 412, 40 } );
	      } },
	    { "handle_count_saturates_low_types_only",
	      []( World_t &world )
	      {
		      for ( u32 iHandle = 0; iHandle < 300; ++iHandle )
			      world.m_rgHandles.push_back( { 516, 5 } );
		      world.m_rgHandles.erase(
		          std::remove_if( world.m_rgHandles.begin(), world.m_rgHandles.end(), []( const FakeHandle_t &handle )
		                          { return handle.m_unPidAndBackTrace == 516 && handle.m_unType != 5; } ),
		          world.m_rgHandles.end() );
	      } },
	    { "pid_table_full_extras",
	      []( World_t &world )
	      {
		      for ( u32 iPid = 0; iPid < 600; ++iPid )
			      world.m_rgHandles.push_back( { 5000 + iPid * 4, static_cast<u8>( iPid % 50 ) } );
		      for ( u32 iPid = 0; iPid < 300; ++iPid )
			      world.m_rgHandles.push_back( { 7000 + iPid * 4, static_cast<u8>( iPid % 50 ) } );
	      } },
	    { "more_than_144_processes",
	      []( World_t &world )
	      {
		      for ( u32 iPid = 0; iPid < 220; ++iPid )
			      AddProcess( world, 1000 + iPid * 4, 4,
			                  L"\\Device\\HarddiskVolume3\\Apps" + std::to_wstring( iPid % 11 ) + L"\\app" +
			                      std::to_wstring( iPid % 17 ) + L".exe" );
	      } },
	    { "more_than_500_in_snapshot",
	      []( World_t &world )
	      {
		      for ( u32 iPid = 0; iPid < 560; ++iPid )
			      AddProcess( world, 1000 + iPid * 4, 4, L"\\Device\\HarddiskVolume3\\A\\a.exe" );
	      } },
	    { "snapshot_fails_reports_60",
	      []( World_t &world )
	      {
		      world.m_bSnapshotFails = true;
		      for ( u32 iPid = 0; iPid < 70; ++iPid )
			      AddProcess( world, 1000 + iPid * 4, 4, L"\\Device\\HarddiskVolume3\\B\\b.exe" );
	      } },
	    { "exited_processes",
	      []( World_t &world )
	      {
		      world.m_Processes[308].m_ulExit = k_ulBaseTime + 1;
		      world.m_Processes[412].m_ulExit = 0xFFFFFFFF00000000ull;
		      world.m_Processes[516].m_ulExit = 1;
	      } },
	    { "age_filter_edges",
	      []( World_t &world )
	      {
		      world.m_Processes[100].m_ulCreate = world.m_ulNow - 1200 * k_ulTicksPerSecond;
		      world.m_Processes[204].m_ulCreate = world.m_ulNow - 1201 * k_ulTicksPerSecond;
		      world.m_Processes[308].m_ulCreate = world.m_ulNow;
		      world.m_Processes[412].m_ulCreate = world.m_ulNow + 5000 * k_ulTicksPerSecond;
		      world.m_Processes[516].m_ulCreate = world.m_ulNow - 1199 * k_ulTicksPerSecond - 1;
	      } },
	    { "times_edges",
	      []( World_t &world )
	      {
		      world.m_Processes[100].m_bTimesFail = true;
		      world.m_Processes[204].m_ulCreate = 0;
		      world.m_Processes[308].m_ulCreate = 0xFFFFFFFFFFFFFFFFull;
		      world.m_Processes[412].m_ulCreate = 9999999;
		      world.m_Processes[516].m_ulCreate = 0x0000000100000000ull;
	      } },
	    { "open_failures",
	      []( World_t &world )
	      {
		      world.m_Processes[100].m_unOpenError = ERROR_ACCESS_DENIED;
		      world.m_Processes[204].m_unOpenError = ERROR_INVALID_PARAMETER;
		      world.m_Processes[308].m_unOpenError = ERROR_ACCESS_DENIED;
		      world.m_Processes[308].m_bOpenGivesMinusOne = true;
		      world.m_Processes[412].m_bLimitedDenied = true;
		      world.m_rgHandles.push_back( { 2000, 3 } );
		      FakeProcess_t missing;
		      missing.m_unOpenError = ERROR_INVALID_PARAMETER;
		      world.m_Processes[2000] = missing;
		      world.m_rgHandles.push_back( { 2004, 3 } );
		      world.m_unDefaultOpenError = ERROR_ACCESS_DENIED;
	      } },
	    { "old_windows_second_open",
	      []( World_t &world )
	      {
		      world.m_unMajor = 5;
		      world.m_unMinor = 1;
		      world.m_Processes[412].m_bLimitedDenied = true;
		      world.m_Processes[516].m_unOpenError = ERROR_ACCESS_DENIED;
	      } },
	    { "win9x_platform",
	      []( World_t &world )
	      {
		      world.m_unPlatform = VER_PLATFORM_WIN32_WINDOWS;
		      world.m_unMajor = 6;
		      world.m_Processes[412].m_bLimitedDenied = true;
	      } },
	    { "name_query_edges",
	      []( World_t &world )
	      {
		      auto &zero = world.m_Processes[100];
		      zero.m_bNameOverride = true;
		      zero.m_unNameResult = 0;
		      auto &full = world.m_Processes[204];
		      full.m_bNameOverride = true;
		      full.m_unNameResult = 0x200;
		      auto &last = world.m_Processes[308];
		      last.m_bNameOverride = true;
		      last.m_unNameResult = 0x1FF;
		      auto &over = world.m_Processes[412];
		      over.m_bNameOverride = true;
		      over.m_unNameResult = 0xFFFFFFFF;
	      } },
	    { "path_shapes",
	      []( World_t &world )
	      {
		      world.m_Processes[100].m_wszImage = L"lonely.exe";
		      world.m_Processes[204].m_wszImage = L"\\lonely.exe";
		      world.m_Processes[308].m_wszImage = L"C:\\trailing\\";
		      world.m_Processes[412].m_wszImage = L"\\Device\\HarddiskVolume3";
		      world.m_Processes[516].m_wszImage = L"";
		      world.m_Processes[620].m_wszImage = L"\\Device\\HarddiskVolume3\\Pro\x0433ram\\\x0438\x043C\x044F.exe";
		      AddProcess( world, 800, 4, L"LONELY.EXE" );
		      AddProcess( world, 804, 4, L"x\\lonely.exe" );
		      AddProcess( world, 808, 4, L"lonely.exe\\inner.exe" );
	      } },
	    { "long_paths",
	      []( World_t &world )
	      {
		      const std::wstring wszLong( 300, L'p' );
		      const std::wstring wszWide( 200, wchar_t( 0x0436 ) );
		      world.m_Processes[100].m_wszImage = L"\\Device\\HarddiskVolume3\\" + wszLong + L"\\a.exe";
		      world.m_Processes[204].m_wszImage = L"\\Device\\HarddiskVolume3\\x\\" + wszLong + L".exe";
		      world.m_Processes[308].m_wszImage = L"\\Device\\HarddiskVolume3\\" + wszWide + L"\\b.exe";
		      world.m_Processes[412].m_wszImage = L"\\Device\\HarddiskVolume3\\y\\" + wszWide + L".exe";
		      world.m_Processes[516].m_wszImage = L"\\Device\\HarddiskVolume7\\" + std::wstring( 487, L'q' );
		      world.m_Processes[620].m_wszImage = L"\\Device\\HarddiskVolume3\\" + std::wstring( 487, L'r' );
	      } },
	    { "drive_lookup_edges", []( World_t &world ) { world.m_bDrivesFail = true; } },
	    { "no_drives", []( World_t &world ) { world.m_rgDrives.clear(); } },
	    { "empty_device_matches_everything", []( World_t &world ) { world.m_rgDrives = { { L'Q', L"" } }; } },
	    { "device_259_chars", []( World_t &world )
	      { world.m_rgDrives = { { L'L', std::wstring( 259, L'z' ) }, { L'C', L"\\Device\\HarddiskVolume3" } }; } },
	    { "handle_query_error", []( World_t &world ) { world.m_unHandleStatus = 0xC0000022; } },
	    { "handle_query_grows", []( World_t &world ) { world.m_cMismatches = 3; } },
	    { "handle_query_too_big_for_first_buffer",
	      []( World_t &world ) { world.m_rgHandles.resize( 70000, FakeHandle_t{ 308, 5 } ); } },
	    { "no_ntquery_export", []( World_t &world ) { world.m_bNoNtQuery = true; } },
	    { "first_alloc_fails", []( World_t &world ) { world.m_iFailAlloc = 0; } },
	    { "alloc_fails_after_growth",
	      []( World_t &world )
	      {
		      world.m_cMismatches = 2;
		      world.m_iFailAlloc = 2;
	      } },
	    { "string_limit_trips",
	      []( World_t &world )
	      {
		      for ( u32 iPid = 0; iPid < 60; ++iPid )
			      AddProcess( world, 1000 + iPid * 4, 4,
			                  L"\\Device\\HarddiskVolume3\\" + std::wstring( 120, wchar_t( L'a' + iPid % 26 ) ) +
			                      std::to_wstring( iPid ) + L"\\" + std::wstring( 100, wchar_t( L'b' + iPid % 25 ) ) +
			                      std::to_wstring( iPid ) + L".exe" );
	      } },
	    { "budget_runs_out",
	      []( World_t &world )
	      {
		      for ( u32 iPid = 0; iPid < 138; ++iPid )
			      AddProcess( world, 1000 + iPid * 4, 4,
			                  L"\\Device\\HarddiskVolume3\\Dir" + std::to_wstring( iPid % 40 ) + L"\\" +
			                      std::wstring( 20 + iPid % 30, L'n' ) + L".exe" );
	      } },
	    { "refs_decide_who_gets_strings",
	      []( World_t &world )
	      {
		      for ( u32 iPid = 0; iPid < 120; ++iPid )
		      {
			      const u32 iDir = iPid < 60 ? 1 : ( iPid < 90 ? 2 : iPid );
			      AddProcess( world, 1000 + iPid * 4, 4,
			                  L"\\Device\\HarddiskVolume3\\Dir" + std::to_wstring( iDir ) + L"\\" +
			                      ( iPid % 3 ? L"common.exe" : L"app" + std::to_wstring( iPid ) + L".exe" ) );
		      }
	      } },
	    { "string_pool_full_faults_in_both",
	      []( World_t &world )
	      {
		      for ( u32 iPid = 0; iPid < 90; ++iPid )
			      AddProcess( world, 1000 + iPid * 4, 4,
			                  L"\\Device\\HarddiskVolume3\\" + std::wstring( 220, wchar_t( L'a' + iPid % 26 ) ) +
			                      std::to_wstring( iPid ) + L"\\" + std::to_wstring( iPid ) + L".exe" );
	      } },
	};

	for ( const auto &scenario : rgScenarios )
	{
		if ( pszOnly && std::strcmp( pszOnly, scenario.first ) )
			continue;
		World_t world = BaseWorld();
		scenario.second( world );
		const u32 cFailuresBefore = s_cFailures;
		const u32 cCasesBefore = s_cCases;
		CompareAllInputs( scenario.first, world );
		std::printf( "%-4s %-40s %u cases\n", s_cFailures == cFailuresBefore ? "OK" : "FAIL", scenario.first,
		             s_cCases - cCasesBefore );
	}
	if ( pszOnly )
		return;

	// Name query fails and writes nothing: the stack garbage must not reach the report. Drive lookup and the string limit
	// would both look at that garbage, in both DLLs, so those stay off.
	{
		World_t world = BaseWorld();
		world.m_bDrivesFail = true;
		world.m_Processes[308].m_bNameOverride = true;
		world.m_Processes[308].m_unNameResult = 0;
		world.m_Processes[308].m_bNameWrites = false;
		const u32 cFailuresBefore = s_cFailures;
		ComparePainted( "name_query_writes_nothing", world, MakeInput( 0, 0, 1200, 0 ), k_cubReport );
		ComparePainted( "name_query_writes_nothing", world, MakeInput( 0, 0, 1200, 3 ), k_cubReport );
		std::printf( "%-4s %-40s 4 cases\n", s_cFailures == cFailuresBefore ? "OK" : "FAIL",
		             "name_query_writes_nothing" );
	}

	{
		World_t world = BaseWorld();
		world.m_bBootFails = true;
		const u32 cFailuresBefore = s_cFailures;
		for ( const u32 cubCapacity : { 0u, 1u, 0xFFFu, 0x1000u, 0x1001u, 0x2000u } )
			CompareCase( "bootstrap_fails", world, MakeInput( 0, 0, 1200, 0 ), cubCapacity, 0 );
		std::printf( "%-4s %-40s 6 cases\n", s_cFailures == cFailuresBefore ? "OK" : "FAIL", "bootstrap_fails" );
	}

	{
		World_t world = BaseWorld();
		const u32 cFailuresBefore = s_cFailures;
		for ( const u32 cubCapacity : { 0u, 1u, 0xFFFu, 0x1000u, 0x1001u, 0x2000u } )
			CompareCase( "capacity", world, MakeInput( 0, 0, 1200, 0 ), cubCapacity, 0 );
		std::printf( "%-4s %-40s 6 cases\n", s_cFailures == cFailuresBefore ? "OK" : "FAIL", "capacity" );
	}
}

World_t RandomWorld( std::mt19937 &random )
{
	const auto Pick = [&]( u32 cValues ) { return static_cast<u32>( random() % cValues ); };

	static const wchar_t *const k_rgpwszRoots[] = { L"\\Device\\HarddiskVolume3\\",
	                                                L"\\device\\HARDDISKVOLUME3\\",
	                                                L"\\Device\\HarddiskVolume10\\",
	                                                L"\\Device\\HarddiskVolume7\\",
	                                                L"",
	                                                L"\\" };
	static const wchar_t *const k_rgpwszDirs[] = { L"Windows\\System32\\",
	                                               L"Windows\\SysWOW64\\",
	                                               L"Program Files\\Steam\\",
	                                               L"Games\\",
	                                               L"",
	                                               L"Users\\\x0418\x0432\x0430\x043D\\AppData\\" };
	static const wchar_t *const k_rgpwszNames[] = {
	    L"svchost.exe", L"SVCHOST.EXE", L"csrss.exe", L"game.exe", L"steam.exe", L"\x0438\x0433\x0440\x0430.exe", L"",
	    L"a.exe" };

	World_t world;
	world.m_rgDrives = { { L'C', L"\\Device\\HarddiskVolume3" }, { L'D', L"\\Device\\HarddiskVolume10" } };
	if ( !Pick( 20 ) )
		world.m_rgDrives.clear();
	if ( !Pick( 30 ) )
		world.m_bDrivesFail = true;

	if ( !Pick( 10 ) )
		world.m_unMajor = 5;
	if ( !Pick( 20 ) )
		world.m_unPlatform = VER_PLATFORM_WIN32_WINDOWS;
	world.m_unDefaultOpenError = Pick( 3 ) ? ERROR_INVALID_PARAMETER : ERROR_ACCESS_DENIED;
	world.m_ulNow = k_ulBaseTime + Pick( 100000 ) * k_ulTicksPerSecond + Pick( 10000000 );

	const u32 cSnapshot = Pick( 4 ) ? Pick( 40 ) : Pick( 260 );
	std::vector<u32> rgunPids;
	for ( u32 iProcess = 0; iProcess < cSnapshot; ++iProcess )
	{
		const u32 unPid = Pick( 30 ) ? ( Pick( 600 ) + 1 ) * 4 : Pick( 2000 ) + 1;
		std::wstring wszImage = k_rgpwszRoots[Pick( 6 )];
		wszImage += k_rgpwszDirs[Pick( 6 )];
		if ( !Pick( 6 ) )
			wszImage += std::wstring( Pick( 200 ), wchar_t( L'd' + Pick( 3 ) ) ) + L"\\";
		wszImage += k_rgpwszNames[Pick( 8 )];
		if ( !Pick( 6 ) )
			wszImage += std::wstring( Pick( 60 ), wchar_t( L'n' + Pick( 3 ) ) );
		u64 ulCreate = world.m_ulNow - Pick( 4000 ) * k_ulTicksPerSecond;
		u64 ulExit = Pick( 8 ) ? 0 : world.m_ulNow - Pick( 100 );
		AddProcess( world, unPid, ( Pick( 100 ) + 1 ) * 4, wszImage, ulCreate, ulExit );

		FakeProcess_t &process = world.m_Processes[unPid];
		switch ( Pick( 24 ) )
		{
		case 0:
			process.m_unOpenError = ERROR_ACCESS_DENIED;
			break;
		case 1:
			process.m_unOpenError = ERROR_INVALID_PARAMETER;
			break;
		case 2:
			process.m_bLimitedDenied = true;
			break;
		case 3:
			process.m_bTimesFail = true;
			break;
		case 4:
			process.m_bNameOverride = true;
			process.m_unNameResult = Pick( 2 ) ? 0 : 0x200;
			break;
		case 5:
			process.m_ulCreate = 0;
			break;
		default:
			break;
		}
		rgunPids.push_back( unPid );
	}

	// An unaligned highest pid never reaches 0 in the walk, both DLLs would call OpenProcess a billion times.
	if ( cSnapshot )
		AddProcess( world, 2404, 4, L"\\Device\\HarddiskVolume3\\Top\\top.exe" );

	const u32 cBruteForceAlive = Pick( 12 );
	for ( u32 iProcess = 0; iProcess < cBruteForceAlive; ++iProcess )
	{
		FakeProcess_t process;
		process.m_wszImage = L"\\Device\\HarddiskVolume3\\Hidden\\h" + std::to_wstring( Pick( 3 ) ) + L".exe";
		process.m_unOpenError = Pick( 4 ) ? 0 : ERROR_ACCESS_DENIED;
		world.m_Processes.emplace( ( Pick( 600 ) + 1 ) * 4, process );
	}

	const u32 cHandles = Pick( 500 );
	for ( u32 iHandle = 0; iHandle < cHandles; ++iHandle )
	{
		u32 unPid = rgunPids.empty() || !Pick( 8 ) ? ( Pick( 900 ) + 1 ) * 4
		                                           : rgunPids[Pick( static_cast<u32>( rgunPids.size() ) )];
		if ( !Pick( 64 ) )
			unPid |= ( Pick( 7 ) + 1 ) << 16;
		world.m_rgHandles.push_back( { unPid, static_cast<u8>( Pick( 3 ) ? Pick( 60 ) : Pick( 256 ) ) } );
	}

	if ( !Pick( 16 ) )
		world.m_cMismatches = Pick( 4 );
	if ( !Pick( 32 ) )
		world.m_unHandleStatus = 0xC0000022;
	if ( !Pick( 64 ) )
		world.m_bNoNtQuery = true;
	if ( !Pick( 64 ) )
		world.m_iFailAlloc = Pick( 2 );
	// A failed snapshot reports 60 entries, fewer than that in EnumProcesses would make both sides read their own stack.
	if ( !Pick( 32 ) && world.m_rgunEnum.size() >= 60 && !( world.m_rgunEnum[59] & 3 ) )
		world.m_bSnapshotFails = true;
	return world;
}

void RunFuzz( u32 cCases )
{
	const u32 cFailuresBefore = s_cFailures;
	const u32 cFaultedBefore = s_cFaulted;
	const auto Pick = []( std::mt19937 &random, u32 cValues ) { return static_cast<u32>( random() % cValues ); };
	for ( u32 iCase = 0; iCase < cCases; ++iCase )
	{
		std::mt19937 random( 0x1DA8FB5Cu + iCase );
		const World_t world = RandomWorld( random );
		const u32 unMin = Pick( random, 4 ) ? 0 : Pick( random, 1200 );
		const u32 unMax = Pick( random, 4 ) ? 0 : unMin + Pick( random, 1200 );
		char szName[32];
		std::snprintf( szName, sizeof( szName ), "fuzz#%u", iCase );
		ComparePainted( szName, world, MakeInput( unMin, unMax, Pick( random, 5000 ), Pick( random, 8 ) ),
		                k_cubReport );
	}
	std::printf( "%-4s %-40s %u cases, %u faulted in both\n", s_cFailures == cFailuresBefore ? "OK" : "FAIL", "fuzz",
	             cCases, s_cFaulted - cFaultedBefore );
}

World_t CaptureRealWorld()
{
	World_t world;
	world.m_unDefaultOpenError = ERROR_INVALID_PARAMETER;

	GetSystemTimeAsFileTime( reinterpret_cast<FILETIME *>( &world.m_ulNow ) );
	OSVERSIONINFOEXA os{};
	os.dwOSVersionInfoSize = sizeof( os );
#pragma warning( suppress : 4996 )
	GetVersionExA( reinterpret_cast<OSVERSIONINFOA *>( &os ) );
	world.m_unPlatform = os.dwPlatformId;
	world.m_unMajor = os.dwMajorVersion;
	world.m_unMinor = os.dwMinorVersion;

	wchar_t wszDrives[260]{};
	GetLogicalDriveStringsW( 250, wszDrives );
	for ( const wchar_t *pwszDrive = wszDrives; *pwszDrive; pwszDrive += wcslen( pwszDrive ) + 1 )
	{
		const wchar_t wszName[3] = { pwszDrive[0], L':', 0 };
		wchar_t wszDevice[260]{};
		if ( QueryDosDeviceW( wszName, wszDevice, 260 ) )
			world.m_rgDrives.push_back( { pwszDrive[0], wszDevice } );
	}

	std::vector<u32> rgunEnum( 500 );
	DWORD cubEnum = 0;
	using PfnEnumProcesses_t = BOOL( WINAPI * )( DWORD *, DWORD, LPDWORD );
	const auto pfnEnum =
	    reinterpret_cast<PfnEnumProcesses_t>( GetProcAddress( LoadLibraryA( "psapi.dll" ), "EnumProcesses" ) );
	pfnEnum( reinterpret_cast<DWORD *>( rgunEnum.data() ), 2000, &cubEnum );
	rgunEnum.resize( cubEnum / 4 );
	world.m_rgunEnum = rgunEnum;

	u32 unHighestPid = 0;
	const HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	PROCESSENTRY32W entry{};
	entry.dwSize = sizeof( entry );
	if ( Process32FirstW( hSnapshot, &entry ) )
	{
		do
		{
			world.m_rgSnapshot.push_back( { entry.th32ProcessID, entry.th32ParentProcessID } );
			unHighestPid = max( unHighestPid, static_cast<u32>( entry.th32ProcessID ) );
		} while ( Process32NextW( hSnapshot, &entry ) );
	}
	CloseHandle( hSnapshot );

	using PfnNtQuery_t = NTSTATUS( WINAPI * )( u32, void *, ULONG, ULONG * );
	const auto pfnQuery =
	    reinterpret_cast<PfnNtQuery_t>( GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtQuerySystemInformation" ) );
	std::vector<u8> rgubHandles;
	NTSTATUS nStatus;
	u32 cubHandles = 0x100000;
	do
	{
		cubHandles *= 2;
		rgubHandles.resize( cubHandles );
		nStatus = pfnQuery( 16, rgubHandles.data(), cubHandles, nullptr );
	} while ( static_cast<u32>( nStatus ) == 0xC0000004 );
	if ( nStatus >= 0 )
	{
		const u32 cHandles = *reinterpret_cast<u32 *>( rgubHandles.data() );
		for ( u32 iHandle = 0; iHandle < cHandles; ++iHandle )
		{
			const u8 *pubEntry = rgubHandles.data() + 4 + iHandle * 16;
			world.m_rgHandles.push_back( { *reinterpret_cast<const u32 *>( pubEntry ), pubEntry[4] } );
		}
	}
	else
		world.m_unHandleStatus = static_cast<u32>( nStatus );

	const auto Capture = [&]( u32 unPid )
	{
		if ( world.m_Processes.count( unPid ) )
			return;
		const HANDLE hProcess = OpenProcess( 0x1000, FALSE, unPid );
		if ( !hProcess )
		{
			FakeProcess_t process;
			process.m_unOpenError = GetLastError();
			world.m_Processes[unPid] = process;
			return;
		}
		using PfnImageName_t = DWORD( WINAPI * )( HANDLE, LPWSTR, DWORD );
		static const auto pfnImageName = reinterpret_cast<PfnImageName_t>(
		    GetProcAddress( LoadLibraryA( "psapi.dll" ), "GetProcessImageFileNameW" ) );
		FakeProcess_t process;
		wchar_t wszImage[512]{};
		const DWORD cchImage = pfnImageName( hProcess, wszImage, 512 );
		process.m_wszImage = wszImage;
		if ( !cchImage )
		{
			process.m_bNameOverride = true;
			process.m_unNameError = GetLastError();
			process.m_unNameResult = 0;
		}
		FILETIME create, exit, kernel, user;
		if ( GetProcessTimes( hProcess, &create, &exit, &kernel, &user ) )
		{
			std::memcpy( &process.m_ulCreate, &create, 8 );
			std::memcpy( &process.m_ulExit, &exit, 8 );
		}
		else
		{
			process.m_bTimesFail = true;
			process.m_unTimesError = GetLastError();
		}
		CloseHandle( hProcess );
		world.m_Processes[unPid] = process;
	};

	for ( const SnapshotRow_t &row : world.m_rgSnapshot )
		Capture( row.m_unPid );
	for ( const u32 unPid : world.m_rgunEnum )
		Capture( unPid );
	for ( const FakeHandle_t &handle : world.m_rgHandles )
		Capture( handle.m_unPidAndBackTrace );
	for ( u32 unPid = unHighestPid; unPid >= 4 && unPid <= unHighestPid; unPid -= 4 )
		Capture( unPid );
	return world;
}

void CompareFrozen( const char *pszName, const World_t &world )
{
	const u32 cFailuresBefore = s_cFailures;
	const u32 cCasesBefore = s_cCases;
	CompareAllInputs( pszName, world );
	ComparePainted( pszName, world, MakeInput( 0, 0, 0x4B0, 0 ), k_cubReport );
	std::printf( "%-4s %-40s %u cases, snapshot=%u handles=%u pids_seen=%u\n",
	             s_cFailures == cFailuresBefore ? "OK" : "FAIL", pszName, s_cCases - cCasesBefore,
	             static_cast<u32>( world.m_rgSnapshot.size() ), static_cast<u32>( world.m_rgHandles.size() ),
	             static_cast<u32>( world.m_Processes.size() ) );
}

// The worker visits at most 144 handle-only pids starting at the snapshot count. Past pid slot 500 it reads their masks from
// beyond its context, so the report gets whatever sits on the stack above the frame: return addresses, different per DLL and
// per run. That is the one thing no comparison can match, so each world below stays clear of it in its own way.
void RunFrozen()
{
	const World_t world = CaptureRealWorld();

	World_t trimmed = world;
	if ( trimmed.m_rgSnapshot.size() > 350 )
		trimmed.m_rgSnapshot.resize( 350 );
	CompareFrozen( "frozen_machine_up_to_350_processes", trimmed );

	World_t onlyListed = world;
	std::vector<u32> rgunListed;
	for ( size_t iRow = 0; iRow < world.m_rgSnapshot.size() && iRow < k_cMaxPids; ++iRow )
		rgunListed.push_back( world.m_rgSnapshot[iRow].m_unPid );
	std::sort( rgunListed.begin(), rgunListed.end() );
	onlyListed.m_rgHandles.erase(
	    std::remove_if(
	        onlyListed.m_rgHandles.begin(), onlyListed.m_rgHandles.end(), [&]( const FakeHandle_t &handle )
	        { return !std::binary_search( rgunListed.begin(), rgunListed.end(), handle.m_unPidAndBackTrace ); } ),
	    onlyListed.m_rgHandles.end() );
	CompareFrozen( "frozen_machine_no_handle_only_pids", onlyListed );
}

void FillFakeImports()
{
	s_FakeImports.GetProcAddress = FakeGetProcAddress;
	s_FakeImports.GetLastError = FakeGetLastError;
	s_FakeImports.EnumProcesses = FakeEnumProcesses;
	s_FakeImports.CreateToolhelp32Snapshot = FakeCreateSnapshot;
	s_FakeImports.Process32FirstW = FakeProcessFirst;
	s_FakeImports.Process32NextW = FakeProcessNext;
	s_FakeImports.CloseHandle = FakeCloseHandle;
	s_FakeImports.VirtualAlloc = FakeVirtualAlloc;
	s_FakeImports.VirtualFree = FakeVirtualFree;
	s_FakeImports.OpenProcess = FakeOpenProcess;
	s_FakeImports.GetProcessImageFileNameW = FakeImageName;
	s_FakeImports.GetProcessTimes = FakeProcessTimes;
	s_FakeImports.GetLogicalDriveStringsW = FakeLogicalDrives;
	s_FakeImports.QueryDosDeviceW = FakeQueryDosDevice;
	s_FakeImports.WideCharToMultiByte = FakeWideToMulti;
	s_FakeImports.GetSystemTimeAsFileTime = FakeSystemTime;
}

} // namespace

namespace vac::bootstrap
{

bool BootstrapMain( const void * ) noexcept
{
	Trace( "BootstrapMain" );
	if ( s_pWorld->m_bBootFails )
		return false;
	*g_pImports = s_FakeImports;
	FillSession( *g_pSession );
	return true;
}

void BootstrapTeardown() noexcept
{
	Trace( "BootstrapTeardown" );
	std::memset( g_pImports, 0, sizeof( *g_pImports ) );
}

} // namespace vac::bootstrap

int main( int argc, char **argv )
{
	setvbuf( stdout, nullptr, _IONBF, 0 );
	if ( argc < 2 )
		return 2;

	bool bFrozen = true;
	u32 cFuzz = 2000;
	const char *pszOnly = nullptr;
	for ( int iArg = 2; iArg < argc; ++iArg )
	{
		if ( !std::strcmp( argv[iArg], "--no-frozen" ) )
			bFrozen = false;
		else if ( !std::strcmp( argv[iArg], "--fuzz" ) && iArg + 1 < argc )
			cFuzz = static_cast<u32>( std::atoi( argv[++iArg] ) );
		else if ( !std::strcmp( argv[iArg], "--only" ) && iArg + 1 < argc )
			pszOnly = argv[++iArg];
		else
			return 2;
	}

	s_pubOriginal = reinterpret_cast<u8 *>( LoadLibraryA( argv[1] ) );
	if ( !s_pubOriginal )
		return 3;

	s_pOriginalImports = *reinterpret_cast<SystemImports_t **>( s_pubOriginal + k_rvaImportsPointer );
	s_pOriginalSession = *reinterpret_cast<ModuleSession_t **>( s_pubOriginal + k_rvaSessionPointer );
	if ( reinterpret_cast<u8 *>( s_pOriginalImports ) != s_pubOriginal + 0x7CF8 ||
	     reinterpret_cast<u8 *>( s_pOriginalSession ) != s_pubOriginal + 0x7788 )
	{
		std::printf( "not the expected build of the module\n" );
		return 4;
	}

	Patch( s_pubOriginal + k_rvaBootstrapMain, FakeOriginalBootstrap );
	Patch( s_pubOriginal + k_rvaBootstrapTeardown, FakeOriginalTeardown );
	FillFakeImports();

	RunScripted( pszOnly );
	RunFuzz( pszOnly ? 0 : cFuzz );
	if ( bFrozen && !pszOnly )
		RunFrozen();

	std::printf( "RESULT %u cases, %u failures, %u faulted in both\n", s_cCases, s_cFailures, s_cFaulted );
	return s_cFailures ? 1 : 0;
}
