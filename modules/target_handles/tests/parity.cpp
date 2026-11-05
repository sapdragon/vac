// Compares target_handles with the original worker.
//
//     target_handles_parity.exe <original module.dll>
//     target_handles_parity.exe <original module.dll> --live
//     target_handles_parity.exe <original module.dll> --no-syscall-dll <rebuild.dll> <input_plain.bin>
//
// Default: both sides run on fake imports with their NT calls patched out. Compared per case: all report bytes, return
// value, output size and the ordered list of import calls.
//
// --live calls only the transports, in both DLLs, on syscall numbers read from this machine's ntdll.
//
// --no-syscall-dll runs both final DLLs with their real bootstrap. Only the key bytes of the input are used. Every syscall
// number is forced to zero first, and the worker returns 44 for a zero number before it reaches a syscall.

#include "../internal/types.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/module.hpp"

#include <windows.h>

#include <array>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <fstream>
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
using namespace vac::workers::target_handles;

namespace vac::workers::target_handles
{
int RunTargetHandles( const Input_t &input, Report_t &report, u32 *pcubOutput ) noexcept;
}

static_assert( offsetof( SystemImports_t, GetCurrentProcessId ) == 432, "original import layout" );
static_assert( offsetof( SystemImports_t, CreateFileA ) == 672, "original import layout" );

namespace
{

constexpr u32 k_rvaWorker = 0x2C31;
constexpr u32 k_rvaBootstrap = 0x4CEC;
constexpr u32 k_rvaOpen = 0x3446;
constexpr u32 k_rvaQueryX64 = 0x32E8;
constexpr u32 k_rvaQuerySysenter = 0x3385;
constexpr u32 k_rvaImportTable = 0x7D38;
constexpr u32 k_rvaImportsPointer = 0x6008;
constexpr u32 k_rvaLoadedLibraries = 0x7CB0;
constexpr u32 k_rvaOpenSsn = 0x7788;
constexpr u32 k_rvaQuerySsn = 0x778C;
constexpr u32 k_rvaUseX64Gate = 0x7790;

constexpr u32 k_unSelfPid = 0x12345678;
constexpr u64 k_ulObject = 0xFFFFFFFF89ABCDEF;

using PfnWorker_t = int( __cdecl * )( const void *, void *, u32 * );

struct Scenario_t
{
	std::vector<std::vector<HandleEntry_t>> m_rgSnapshots;
	std::vector<u32> m_rgunQueryStatuses;
	u32 m_unInitialStatus = 0;
	u32 m_unSecondStatus = 0;
	u32 m_unDetailStatus = 0;
	u32 m_unHandle = 0x44;
	u32 m_unTickStep = 0;
	u32 m_iFailAllocation = 0;
	bool m_bBootFails = false;
	bool m_bNoPath = false;
	bool m_bNoFile = false;
	bool m_bNoFileInfo = false;
	std::wstring m_wszPath = L"\\Device\\HarddiskVolume7\\fixture.exe";
};

Scenario_t s_Scenario;
Input_t s_Input{};
u32 s_cQueries;
u32 s_cOpens;
u32 s_cTicks;
u32 s_cAllocations;
SystemImports_t s_Apis{};
u8 *s_pubOriginal;
u32 s_cCases;
u32 s_cFailures;
std::string s_szTrace;

void Trace( const char *pszFormat, ... )
{
	char szLine[300];
	va_list args;
	va_start( args, pszFormat );
	vsnprintf( szLine, sizeof( szLine ), pszFormat, args );
	va_end( args );
	s_szTrace += szLine;
	s_szTrace += '\n';
}

LONG CALLBACK LogException( PEXCEPTION_POINTERS pException )
{
	std::printf( "exception %08lx at %p (original+%x) bad address %p queries=%u\n",
	             pException->ExceptionRecord->ExceptionCode, pException->ExceptionRecord->ExceptionAddress,
	             static_cast<u32>( static_cast<u8 *>( pException->ExceptionRecord->ExceptionAddress ) - s_pubOriginal ),
	             reinterpret_cast<void *>( pException->ExceptionRecord->ExceptionInformation[1] ), s_cQueries );
	std::fflush( stdout );
	return EXCEPTION_CONTINUE_SEARCH;
}

void ResetCounters()
{
	s_cQueries = s_cOpens = s_cTicks = s_cAllocations = 0;
	s_szTrace.clear();
}

HandleEntry_t MakeHandle( u32 unPid, u16 unHandle = 0x70, u32 unAccess = 0x1000, u64 ulObject = k_ulObject,
                          u8 unType = 7 )
{
	return { unPid, unType, 0, unHandle, ulObject, unAccess, 0 };
}

DWORD WINAPI FakeCurrentPid()
{
	Trace( "GetCurrentProcessId" );
	return k_unSelfPid;
}

DWORD WINAPI FakeLastError()
{
	Trace( "GetLastError" );
	return 77;
}

DWORD WINAPI FakeTick()
{
	Trace( "GetTickCount" );
	return s_cTicks++ * s_Scenario.m_unTickStep;
}

BOOL WINAPI FakeYield()
{
	Trace( "SwitchToThread" );
	return TRUE;
}

BOOL WINAPI FakeClose( HANDLE hObject )
{
	Trace( "CloseHandle %p", hObject );
	return TRUE;
}

LPVOID WINAPI FakeAllocate( LPVOID pAddress, SIZE_T cub, DWORD unType, DWORD unProtect )
{
	Trace( "VirtualAlloc %p %x %x %x", pAddress, static_cast<u32>( cub ), unType, unProtect );
	++s_cAllocations;
	if ( s_Scenario.m_iFailAllocation && s_cAllocations == s_Scenario.m_iFailAllocation )
		return nullptr;
	return VirtualAlloc( nullptr, 65536, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
}

BOOL WINAPI FakeRelease( LPVOID pAddress, SIZE_T cub, DWORD unType )
{
	Trace( "VirtualFree %x %x", static_cast<u32>( cub ), unType );
	return VirtualFree( pAddress, 0, MEM_RELEASE );
}

u32 __cdecl FakeOpen( HANDLE *phProcess, u32 unAccess, u32 unPid )
{
	Trace( "NtOpenProcess %x %u", unAccess, unPid );
	++s_cOpens;
	u32 unStatus;
	if ( s_cOpens == 1 )
		unStatus = s_Scenario.m_unInitialStatus;
	else if ( s_cOpens == 2 && s_Scenario.m_unInitialStatus == 5 && unAccess == 0x400 )
		unStatus = s_Scenario.m_unSecondStatus;
	else
		unStatus = s_Scenario.m_unDetailStatus;
	if ( !unStatus )
		*phProcess = reinterpret_cast<HANDLE>( static_cast<uptr>( s_Scenario.m_unHandle ) );
	return unStatus;
}

u32 FakeQuery( void *pBuffer, u32 cubBuffer )
{
	Trace( "NtQuerySystemInformation %x", cubBuffer );
	const u32 iQuery = s_cQueries++;
	const u32 unStatus = iQuery < s_Scenario.m_rgunQueryStatuses.size() ? s_Scenario.m_rgunQueryStatuses[iQuery] : 0;
	if ( unStatus )
		return unStatus;

	const auto &rgRows =
	    s_Scenario
	        .m_rgSnapshots[iQuery < s_Scenario.m_rgSnapshots.size() ? iQuery : s_Scenario.m_rgSnapshots.size() - 1];
	auto *pubBuffer = static_cast<u8 *>( pBuffer );
	std::memset( pubBuffer, 0, 65536 );
	*reinterpret_cast<u32 *>( pubBuffer ) = static_cast<u32>( rgRows.size() );
	for ( u32 iRow = 0; iRow < rgRows.size(); ++iRow )
	{
		const HandleEntry_t &row = rgRows[iRow];
		if ( s_Input.m_unUseX64Gate )
		{
			std::memcpy( pubBuffer + 8 + iRow * 24, &row, 24 );
		}
		else
		{
			u8 *pubEntry = pubBuffer + 4 + iRow * 16;
			std::memcpy( pubEntry, &row, 8 );
			*reinterpret_cast<u32 *>( pubEntry + 8 ) = static_cast<u32>( row.m_ulObject );
			*reinterpret_cast<u32 *>( pubEntry + 12 ) = row.m_unGrantedAccess;
		}
	}
	return 0;
}

DWORD WINAPI FakeImageName( HANDLE hProcess, LPWSTR pwszOut, DWORD cchOut )
{
	Trace( "GetProcessImageFileNameW %p %u", hProcess, cchOut );
	if ( s_Scenario.m_bNoPath )
		return 0;
	std::wcsncpy( pwszOut, s_Scenario.m_wszPath.c_str(), cchOut - 1 );
	pwszOut[cchOut - 1] = 0;
	return static_cast<DWORD>( std::wcslen( pwszOut ) );
}

DWORD WINAPI FakeModuleName( HANDLE hProcess, HMODULE hModule, LPWSTR pwszOut, DWORD cchOut )
{
	Trace( "GetModuleFileNameExW %p %p %u", hProcess, hModule, cchOut );
	if ( s_Scenario.m_bNoPath )
		return 0;
	std::wcsncpy( pwszOut, s_Scenario.m_wszPath.c_str(), cchOut - 1 );
	pwszOut[cchOut - 1] = 0;
	return static_cast<DWORD>( std::wcslen( pwszOut ) );
}

HANDLE WINAPI FakeCreateFile( LPCSTR pszPath, DWORD unAccess, DWORD unShare, LPSECURITY_ATTRIBUTES pSecurity,
                              DWORD unCreation, DWORD unAttributes, HANDLE hTemplate )
{
	Trace( "CreateFileA '%s' %x %x %p %x %x %p", pszPath, unAccess, unShare, pSecurity, unCreation, unAttributes,
	       hTemplate );
	return s_Scenario.m_bNoFile ? INVALID_HANDLE_VALUE : reinterpret_cast<HANDLE>( 0x99 );
}

BOOL WINAPI FakeFileInfo( HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION pInformation )
{
	Trace( "GetFileInformationByHandle %p", hFile );
	if ( s_Scenario.m_bNoFileInfo )
		return FALSE;
	std::memset( pInformation, 0, sizeof( *pInformation ) );
	pInformation->dwVolumeSerialNumber = 0x13572468;
	pInformation->nFileIndexLow = 0x24681357;
	pInformation->nFileIndexHigh = 0x89ABCDEF;
	return TRUE;
}

// The original passes ECX and EDX plus one caller cleaned stack argument. MSVC's __fastcall would pop it in the callee.
__declspec( naked ) u32 OriginalOpenThunk()
{
	__asm
	{
		push dword ptr [esp+4]
		push edx
		push ecx
		call FakeOpen
		add esp, 12
		ret
	}
}

u32 __cdecl FakeQueryX64( u64, u64 ulBuffer, u64 ulCubBuffer, u64 )
{
	return FakeQuery( reinterpret_cast<void *>( static_cast<uptr>( ulBuffer ) ), static_cast<u32>( ulCubBuffer ) );
}

u32 __cdecl FakeQuerySysenter( u32, void *pBuffer, u32 cubBuffer, void * )
{
	return FakeQuery( pBuffer, cubBuffer );
}

bool __fastcall FakeOriginalBootstrap( void * )
{
	Trace( "BootstrapMain" );
	if ( s_Scenario.m_bBootFails )
		return false;
	std::memcpy( s_pubOriginal + k_rvaImportTable, &s_Apis, sizeof( s_Apis ) );
	*reinterpret_cast<const SystemImports_t **>( s_pubOriginal + k_rvaImportsPointer ) = &s_Apis;
	*reinterpret_cast<u32 *>( s_pubOriginal + k_rvaLoadedLibraries ) = 0;
	return true;
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

u32 CallOriginalOpen( HANDLE *phProcess, u32 unAccess, u32 unPid )
{
	void *pfnOpen = s_pubOriginal + k_rvaOpen;
	u32 unResult;
	__asm
	{
		mov ecx, phProcess
		mov edx, unAccess
		push unPid
		call pfnOpen
		add esp, 4
		mov unResult, eax
	}
	return unResult;
}

u32 SyscallNumber( const std::vector<u8> &rgubNtdll, const char *pszFunction )
{
	const auto *pDos = reinterpret_cast<const IMAGE_DOS_HEADER *>( rgubNtdll.data() );
	const auto *pNt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>( rgubNtdll.data() + pDos->e_lfanew );
	const auto *pSections = IMAGE_FIRST_SECTION( pNt );
	const auto RvaToOffset = [&]( u32 unRva ) -> u32
	{
		for ( u32 iSection = 0; iSection < pNt->FileHeader.NumberOfSections; ++iSection )
		{
			if ( unRva >= pSections[iSection].VirtualAddress &&
			     unRva - pSections[iSection].VirtualAddress < pSections[iSection].SizeOfRawData )
				return pSections[iSection].PointerToRawData + unRva - pSections[iSection].VirtualAddress;
		}
		return unRva;
	};

	const auto &exportDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	const auto *pExports =
	    reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>( rgubNtdll.data() + RvaToOffset( exportDir.VirtualAddress ) );
	const auto *punNames = reinterpret_cast<const u32 *>( rgubNtdll.data() + RvaToOffset( pExports->AddressOfNames ) );
	const auto *punOrdinals =
	    reinterpret_cast<const u16 *>( rgubNtdll.data() + RvaToOffset( pExports->AddressOfNameOrdinals ) );
	const auto *punFunctions =
	    reinterpret_cast<const u32 *>( rgubNtdll.data() + RvaToOffset( pExports->AddressOfFunctions ) );
	for ( u32 iName = 0; iName < pExports->NumberOfNames; ++iName )
	{
		if ( !std::strcmp( reinterpret_cast<const char *>( rgubNtdll.data() + RvaToOffset( punNames[iName] ) ),
		                   pszFunction ) )
		{
			const u8 *pubStub = rgubNtdll.data() + RvaToOffset( punFunctions[punOrdinals[iName]] );
			if ( pubStub[0] == 0x4C && pubStub[1] == 0x8B && pubStub[2] == 0xD1 && pubStub[3] == 0xB8 )
				return *reinterpret_cast<const u32 *>( pubStub + 4 );
		}
	}
	return 0;
}

int RunLive()
{
	std::ifstream file( "C:\\Windows\\Sysnative\\ntdll.dll", std::ios::binary );
	const std::vector<u8> rgubNtdll( ( std::istreambuf_iterator<char>( file ) ), std::istreambuf_iterator<char>() );
	if ( rgubNtdll.empty() )
		return 7;

	const u32 unOpenSsn = SyscallNumber( rgubNtdll, "NtOpenProcess" );
	const u32 unQuerySsn = SyscallNumber( rgubNtdll, "NtQuerySystemInformation" );
	if ( !unOpenSsn || !unQuerySsn )
		return 8;
	std::printf( "LIVE SSNs open=%u query=%u\n", unOpenSsn, unQuerySsn );
	std::fflush( stdout );

	*reinterpret_cast<u32 *>( s_pubOriginal + k_rvaOpenSsn ) = unOpenSsn;
	*reinterpret_cast<u32 *>( s_pubOriginal + k_rvaQuerySsn ) = unQuerySsn;
	*reinterpret_cast<u32 *>( s_pubOriginal + k_rvaUseX64Gate ) = 1;
	g_unOpenSsn = unOpenSsn;
	g_unQuerySsn = unQuerySsn;
	g_bUseX64Gate = true;

	u32 cFailed = 0;
	u32 cChecks = 0;
	for ( const u32 unPid : { 0u, 0xFFFFFFFCu, static_cast<u32>( GetCurrentProcessId() ) } )
	{
		HANDLE hOriginal = nullptr;
		HANDLE hRebuild = nullptr;
		const u32 unOriginal = CallOriginalOpen( &hOriginal, 0x1000, unPid );
		const u32 unRebuild = static_cast<u32>( OpenProcessBySyscall( &hRebuild, 0x1000, unPid ) );
		const bool bEqual = unOriginal == unRebuild && ( unOriginal != 0 || ( hOriginal && hRebuild ) );
		std::printf( "LIVE open pid=%u status=%08x/%08x %s\n", unPid, unOriginal, unRebuild, bEqual ? "OK" : "DIFF" );
		std::fflush( stdout );
		++cChecks;
		cFailed += !bEqual;
		if ( !unOriginal && hOriginal )
			CloseHandle( hOriginal );
		if ( !unRebuild && hRebuild )
			CloseHandle( hRebuild );
	}

	using PfnQueryX64_t = u32( __cdecl * )( u64, u64, u64, u64 );
	const auto pfnOriginalQuery = reinterpret_cast<PfnQueryX64_t>( s_pubOriginal + k_rvaQueryX64 );
	for ( const u32 cubBuffer : { 16u, 0x800000u } )
	{
		auto *pubOriginal =
		    static_cast<u8 *>( VirtualAlloc( nullptr, cubBuffer, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE ) );
		auto *pubRebuild =
		    static_cast<u8 *>( VirtualAlloc( nullptr, cubBuffer, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE ) );
		const u32 unOriginal = pfnOriginalQuery( 16, reinterpret_cast<uptr>( pubOriginal ), cubBuffer, 0 );
		const u32 unRebuild = NtQuerySystemInformationX64( 16, PointerToX64( pubRebuild ), cubBuffer, 0 );
		const bool bEqual = unOriginal == unRebuild && ( unOriginal || ( *reinterpret_cast<u32 *>( pubOriginal ) > 0 &&
		                                                                 *reinterpret_cast<u32 *>( pubRebuild ) > 0 ) );
		std::printf( "LIVE query size=%u status=%08x/%08x %s\n", cubBuffer, unOriginal, unRebuild,
		             bEqual ? "OK" : "DIFF" );
		std::fflush( stdout );
		++cChecks;
		cFailed += !bEqual;
		VirtualFree( pubOriginal, 0, MEM_RELEASE );
		VirtualFree( pubRebuild, 0, MEM_RELEASE );
	}

	std::printf( "LIVE RESULT %u checks, %u failures\n", cChecks, cFailed );
	return cFailed ? 1 : 0;
}

PfnWorker_t FindWorker( HMODULE hModule )
{
	auto *pubBase = reinterpret_cast<u8 *>( hModule );
	const auto *pNt =
	    reinterpret_cast<IMAGE_NT_HEADERS *>( pubBase + reinterpret_cast<IMAGE_DOS_HEADER *>( pubBase )->e_lfanew );
	const auto *pSections = IMAGE_FIRST_SECTION( pNt );
	for ( u32 iSection = 0; iSection < pNt->FileHeader.NumberOfSections; ++iSection )
	{
		if ( pSections[iSection].Characteristics & IMAGE_SCN_MEM_EXECUTE )
			continue;
		for ( u32 ib = 0; ib + 48 <= pSections[iSection].Misc.VirtualSize; ib += 4 )
		{
			u8 *pubNode = pubBase + pSections[iSection].VirtualAddress + ib;
			if ( *reinterpret_cast<u32 *>( pubNode + 4 ) == k_unModuleId &&
			     *reinterpret_cast<u32 *>( pubNode + 8 ) == 1 )
			{
				const auto pfnWorker = *reinterpret_cast<PfnWorker_t *>( pubNode + 12 );
				const auto *pubWorker = reinterpret_cast<const u8 *>( pfnWorker );
				if ( pubWorker >= pubBase && pubWorker < pubBase + pNt->OptionalHeader.SizeOfImage )
					return pfnWorker;
			}
		}
	}
	return nullptr;
}

// Both final DLLs with the real bootstrap. All syscall numbers are zero, so the first open returns 44 without any syscall.
int RunNoSyscallDll( const char *pszRebuild, const char *pszSeed )
{
	const HMODULE hRebuild = LoadLibraryA( pszRebuild );
	if ( !hRebuild )
		return 4;
	const PfnWorker_t pfnRebuild = FindWorker( hRebuild );
	if ( !pfnRebuild )
		return 5;
	const auto pfnOriginal = reinterpret_cast<PfnWorker_t>( s_pubOriginal + k_rvaWorker );

	Input_t input{};
	std::ifstream seed( pszSeed, std::ios::binary );
	seed.read( reinterpret_cast<char *>( &input ), sizeof( input ) );
	if ( !seed )
		return 6;
	input.m_unTargetPid = 0;
	input.m_unQuerySsn = 0;
	input.m_unOpenSsn = 0;

	u32 cFailed = 0;
	u32 cChecks = 0;
	for ( const u32 unUseGate : { 0u, 1u, 0u, 1u } )
	{
		input.m_unUseX64Gate = unUseGate;
		for ( const u32 cubCapacity : { 0u, 4096u } )
		{
			std::array<u8, 4096> rgubOriginal;
			std::array<u8, 4096> rgubRebuild;
			rgubOriginal.fill( 0xCD );
			rgubRebuild.fill( 0xCD );
			u32 cubOriginal = cubCapacity;
			u32 cubRebuild = cubCapacity;
			const int nOriginal = pfnOriginal( &input, rgubOriginal.data(), &cubOriginal );
			const int nRebuild = pfnRebuild( &input, rgubRebuild.data(), &cubRebuild );
			const EScanStatus eStatus = reinterpret_cast<const Report_t *>( rgubOriginal.data() )->m_eStatus;
			const bool bEqual = nOriginal == nRebuild && cubOriginal == cubRebuild && rgubOriginal == rgubRebuild &&
			                    eStatus == EScanStatus::NoSyscallNumber;
			std::printf( "DLL gate=%u cap=%u ret=%d/%d size=%u/%u status=%u %s\n", unUseGate, cubCapacity, nOriginal,
			             nRebuild, cubOriginal, cubRebuild, static_cast<u32>( eStatus ), bEqual ? "OK" : "DIFF" );
			++cChecks;
			cFailed += !bEqual;
		}
	}
	std::printf( "DLL RESULT %u checks, %u failures\n", cChecks, cFailed );
	return cFailed ? 1 : 0;
}

void Run( const std::string &szName, bool bWide, Scenario_t scenario, u32 unTargetPid = 4321 )
{
	s_Scenario = std::move( scenario );
	s_Input = {};
	s_Input.m_unTargetPid = unTargetPid;
	s_Input.m_unUseX64Gate = bWide;
	s_Input.m_unQuerySsn = 54;
	s_Input.m_unOpenSsn = 38;
	if ( szName.find( "missing_query" ) != std::string::npos )
		s_Input.m_unQuerySsn = 0;
	if ( s_Scenario.m_rgSnapshots.empty() )
		s_Scenario.m_rgSnapshots = { { MakeHandle( k_unSelfPid, 0x44 ) } };

	static std::array<u8, 4096> s_rgubExpected;
	static std::array<u8, 4096> s_rgubActual;
	s_rgubExpected.fill( 0xCD );
	s_rgubActual.fill( 0xCD );

	u32 cubExpected = 0;
	ResetCounters();
	const int nExpected =
	    reinterpret_cast<PfnWorker_t>( s_pubOriginal + k_rvaWorker )( &s_Input, s_rgubExpected.data(), &cubExpected );
	const std::string szExpectedTrace = s_szTrace;

	u32 cubActual = 0;
	ResetCounters();
	const int nActual = RunTargetHandles( s_Input, *reinterpret_cast<Report_t *>( s_rgubActual.data() ), &cubActual );

	const bool bEqual = nExpected == nActual && cubExpected == cubActual && cubExpected == 4096 &&
	                    s_rgubExpected == s_rgubActual && szExpectedTrace == s_szTrace;
	++s_cCases;
	if ( bEqual )
	{
		std::printf( "OK %s_%d\n", szName.c_str(), bWide );
	}
	else
	{
		++s_cFailures;
		std::printf( "DIFF %s_%d ret=%d/%d size=%u/%u\n", szName.c_str(), bWide, nExpected, nActual, cubExpected,
		             cubActual );
		u32 cShown = 0;
		for ( u32 ib = 0; ib < 4096 && cShown < 12; ++ib )
		{
			if ( s_rgubExpected[ib] != s_rgubActual[ib] )
			{
				std::printf( " +%x %02x/%02x\n", ib, s_rgubExpected[ib], s_rgubActual[ib] );
				++cShown;
			}
		}
		if ( szExpectedTrace != s_szTrace )
		{
			size_t ib = 0;
			while ( ib < szExpectedTrace.size() && ib < s_szTrace.size() && szExpectedTrace[ib] == s_szTrace[ib] )
				++ib;
			const size_t ibStart = ib > 60 ? ib - 60 : 0;
			std::printf( " trace at %u\n  original: %.160s\n  rebuild:  %.160s\n", static_cast<u32>( ib ),
			             szExpectedTrace.c_str() + ibStart, s_szTrace.c_str() + ibStart );
		}
	}
	std::fflush( stdout );
}

void RunScenarios()
{
	for ( const bool bWide : { false, true } )
	{
		Run( "no_owners", bWide, {} );

		Scenario_t base;
		base.m_rgSnapshots = { { MakeHandle( k_unSelfPid, 0x44 ), MakeHandle( 100 ), MakeHandle( 100, 0x74, 0x410 ),
		                         MakeHandle( 200 ), MakeHandle( 200 ), MakeHandle( 300, 1, 1, k_ulObject, 8 ),
		                         MakeHandle( 400, 1, 1, k_ulObject + 1 ) } };
		Run( "dedup_rights_type_object", bWide, base );

		Scenario_t scenario = base;
		scenario.m_bBootFails = true;
		Run( "bootstrap_fails", bWide, scenario );

		scenario = base;
		scenario.m_unInitialStatus = 0xC0000022;
		Run( "open_denied", bWide, scenario );

		scenario = base;
		scenario.m_unInitialStatus = 5;
		Run( "fallback_access", bWide, scenario );

		scenario.m_bNoPath = true;
		Run( "fallback_access_no_path", bWide, scenario );

		scenario = base;
		scenario.m_unInitialStatus = 5;
		scenario.m_bNoFile = true;
		Run( "fallback_access_no_file", bWide, scenario );

		scenario = base;
		scenario.m_unInitialStatus = 5;
		scenario.m_unSecondStatus = 0xC000000B;
		Run( "fallback_failed", bWide, scenario );

		scenario = base;
		scenario.m_unHandle = 0x10000;
		Run( "handle_too_large", bWide, scenario );

		scenario = base;
		scenario.m_unHandle = 0xFFFF;
		scenario.m_rgSnapshots[0][0] = MakeHandle( k_unSelfPid, 0xFFFF );
		Run( "handle_at_limit", bWide, scenario );

		scenario = base;
		scenario.m_iFailAllocation = 1;
		Run( "initial_alloc_failed", bWide, scenario );

		scenario = base;
		scenario.m_rgunQueryStatuses = { 0xC0000004, 0xC0000004, 0 };
		Run( "grow_twice", bWide, scenario );

		scenario = base;
		scenario.m_rgunQueryStatuses = { 0xC0000004 };
		scenario.m_iFailAllocation = 2;
		Run( "grow_alloc_failed", bWide, scenario );

		scenario = base;
		scenario.m_rgunQueryStatuses.assign( 10, 0xC0000004 );
		Run( "grow_limit_frees_twice", bWide, scenario );

		scenario = base;
		scenario.m_rgunQueryStatuses = { 0xC0000001 };
		Run( "query_failed", bWide, scenario );

		Run( "missing_query", bWide, base );

		scenario = base;
		scenario.m_rgunQueryStatuses = { 0, 0xC0000001 };
		Run( "later_query_failed", bWide, scenario );

		scenario = base;
		scenario.m_rgunQueryStatuses = { 0, 0, 0xC0000004, 0, 0xC0000004, 0xC0000004, 0 };
		Run( "later_query_grows", bWide, scenario );

		scenario = base;
		scenario.m_rgSnapshots = { {} };
		Run( "empty", bWide, scenario );

		scenario = base;
		scenario.m_rgSnapshots = { { MakeHandle( 999, 0x44 ) } };
		Run( "self_missing", bWide, scenario );

		scenario = base;
		scenario.m_rgSnapshots = { { MakeHandle( k_unSelfPid, 0x44 ), MakeHandle( k_unSelfPid, 0x44 ) } };
		Run( "duplicate_self", bWide, scenario );

		scenario = base;
		scenario.m_rgSnapshots = {
		    { MakeHandle( 100 ), MakeHandle( k_unSelfPid, 0x44 ), MakeHandle( k_unSelfPid, 0x44, 1, 5, 9 ) } };
		Run( "self_handle_later_duplicate", bWide, scenario );

		scenario = base;
		scenario.m_unTickStep = 6000;
		Run( "timeout_immediate", bWide, scenario );

		scenario = base;
		scenario.m_unTickStep = 5999;
		Run( "timeout_just_below", bWide, scenario );

		scenario = base;
		scenario.m_unTickStep = 1000;
		Run( "timeout_after_passes", bWide, scenario );

		scenario = base;
		scenario.m_unDetailStatus = 0xC000000B;
		Run( "owner_open_failed", bWide, scenario );

		scenario = base;
		scenario.m_bNoPath = true;
		Run( "image_failed", bWide, scenario );

		scenario = base;
		scenario.m_bNoFile = true;
		Run( "file_failed", bWide, scenario );

		scenario = base;
		scenario.m_bNoFileInfo = true;
		Run( "file_info_failed", bWide, scenario );

		scenario = base;
		scenario.m_wszPath =
		    L"\\Device\\HarddiskVolume123\\a_very_long_directory_name\\long_image_filename_0123456789.exe";
		Run( "long_tail", bWide, scenario );

		scenario = base;
		scenario.m_wszPath = L"C:\\test\\\u0442\u0435\u0441\u0442.exe";
		Run( "utf8", bWide, scenario );

		scenario = base;
		scenario.m_wszPath = L"a";
		Run( "short_path", bWide, scenario );

		scenario = base;
		scenario.m_wszPath = std::wstring( 39, L'w' );
		Run( "path_39_bytes", bWide, scenario );

		scenario = base;
		scenario.m_wszPath = std::wstring( 40, L'x' );
		Run( "path_40_bytes", bWide, scenario );

		scenario = base;
		scenario.m_wszPath = std::wstring( 41, L'y' );
		Run( "path_41_bytes", bWide, scenario );

		scenario = base;
		scenario.m_wszPath = std::wstring( 300, L'z' );
		Run( "path_longer_than_buffer", bWide, scenario );

		scenario = base;
		scenario.m_wszPath = std::wstring( 200, wchar_t( 0x0436 ) );
		Run( "path_utf8_overflow", bWide, scenario );

		for ( const u32 cOwners : { 1u, 10u, 11u, 12u, 60u, 61u, 62u, 63u, 100u } )
		{
			scenario = {};
			scenario.m_rgSnapshots = { { MakeHandle( k_unSelfPid, 0x44 ) } };
			for ( u32 iOwner = 0; iOwner < cOwners; ++iOwner )
				scenario.m_rgSnapshots[0].push_back( MakeHandle( 1000 + iOwner ) );
			Run( "owners_" + std::to_string( cOwners ), bWide, scenario );
		}

		scenario = base;
		scenario.m_rgSnapshots.push_back( { MakeHandle( k_unSelfPid, 0x44 ), MakeHandle( 500 ) } );
		Run( "changing_snapshot", bWide, scenario );

		scenario = base;
		scenario.m_rgSnapshots[0].push_back( MakeHandle( 100, 1, 1, k_ulObject + 99 ) );
		Run( "count_all_same_type", bWide, scenario );

		scenario = base;
		scenario.m_rgSnapshots[0].push_back( MakeHandle( 0, 2, 0 ) );
		scenario.m_rgSnapshots[0].push_back( MakeHandle( 0, 3, 0x20 ) );
		Run( "owner_pid_zero", bWide, scenario );

		scenario = base;
		scenario.m_rgSnapshots[0].push_back( MakeHandle( 0x00030000u | 100 ) );
		scenario.m_rgSnapshots[0].push_back( MakeHandle( 0x00030000u | k_unSelfPid ) );
		Run( "backtrace_bits_in_pid", bWide, scenario );

		scenario = base;
		for ( auto &row : scenario.m_rgSnapshots[0] )
			row.m_ulObject = 0x0000000012345678;
		Run( "positive_object", bWide, scenario );

		scenario = base;
		scenario.m_rgSnapshots[0].insert( scenario.m_rgSnapshots[0].begin(), MakeHandle( k_unSelfPid, 0x45 ) );
		scenario.m_rgSnapshots[0].push_back( MakeHandle( k_unSelfPid, 0x46 ) );
		Run( "own_other_handles_ignored", bWide, scenario );

		Run( "target_pid_passes_through", bWide, base, 0xFFFFFFFC );
		Run( "target_pid_zero", bWide, base, 0 );
	}
}

} // namespace

namespace vac::bootstrap
{

bool BootstrapMain( const void * ) noexcept
{
	Trace( "BootstrapMain" );
	if ( s_Scenario.m_bBootFails )
		return false;
	*g_pImports = s_Apis;
	return true;
}

void BootstrapTeardown() noexcept
{
	std::memset( g_pImports, 0, sizeof( *g_pImports ) );
}

} // namespace vac::bootstrap

int main( int argc, char **argv )
{
	setvbuf( stdout, nullptr, _IONBF, 0 );
	AddVectoredExceptionHandler( 1, LogException );
	if ( argc < 2 )
		return 2;

	s_pubOriginal = reinterpret_cast<u8 *>( LoadLibraryA( argv[1] ) );
	if ( !s_pubOriginal )
		return 3;

	if ( argc == 3 && !std::strcmp( argv[2], "--live" ) )
		return RunLive();
	if ( argc == 5 && !std::strcmp( argv[2], "--no-syscall-dll" ) )
		return RunNoSyscallDll( argv[3], argv[4] );
	if ( argc != 2 )
		return 2;

	Patch( s_pubOriginal + k_rvaBootstrap, FakeOriginalBootstrap );
	Patch( s_pubOriginal + k_rvaOpen, OriginalOpenThunk );
	Patch( s_pubOriginal + k_rvaQueryX64, FakeQueryX64 );
	Patch( s_pubOriginal + k_rvaQuerySysenter, FakeQuerySysenter );

	// The rebuild has plain cdecl for these, so the same fakes go straight in. No real syscall can run in this mode.
	Patch( reinterpret_cast<void *>( &OpenProcessBySyscall ), FakeOpen );
	Patch( reinterpret_cast<void *>( &NtQuerySystemInformationX64 ), FakeQueryX64 );
	Patch( reinterpret_cast<void *>( &NtQuerySystemInformationSysenter ), FakeQuerySysenter );

	s_Apis.GetCurrentProcessId = FakeCurrentPid;
	s_Apis.GetLastError = FakeLastError;
	s_Apis.GetTickCount = FakeTick;
	s_Apis.SwitchToThread = FakeYield;
	s_Apis.CloseHandle = FakeClose;
	s_Apis.VirtualAlloc = FakeAllocate;
	s_Apis.VirtualFree = FakeRelease;
	s_Apis.GetProcessImageFileNameW = FakeImageName;
	s_Apis.GetModuleFileNameExW = FakeModuleName;
	s_Apis.WideCharToMultiByte = WideCharToMultiByte;
	s_Apis.CreateFileA = FakeCreateFile;
	s_Apis.GetFileInformationByHandle = FakeFileInfo;

	RunScenarios();

	std::printf( "RESULT %u cases, %u failures\n", s_cCases, s_cFailures );
	return s_cFailures ? 1 : 0;
}
