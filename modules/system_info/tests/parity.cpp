// Fault injection parity for system_info, the paths a healthy machine never takes.
//
//     system_info_parity.exe <original.dll> <rebuild.dll> <decrypted_input.bin>
//
// Each scenario runs the original, the rebuild and the original again in this process, with the same API
// faults. Bytes that differ between the two original runs are noise. Time fields must land between the two
// original runs, so their high bytes get checked as well, and the handle must be open in both or in neither.
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace
{

using Worker_t = int( __cdecl * )( const unsigned char *, unsigned char *, unsigned * );

constexpr unsigned k_cubWritten = 3072;
constexpr unsigned k_cubAllocated = 4096;
constexpr unsigned k_ibTargetPid = 0x60;
constexpr unsigned k_ibXorKey = 0x64;
constexpr unsigned k_ibStatus = 0x14;
constexpr unsigned k_ibSystemTimeStart = 0x20;
constexpr unsigned k_ibSystemTimeEnd = 0x28;
constexpr unsigned k_ibTickStart = 0x30;
constexpr unsigned k_ibTickEnd = 0x34;
constexpr unsigned k_ibCurrentTime = 0x38;
constexpr unsigned k_ibTimesEnd = 0x40;
constexpr unsigned k_ibNtdllStatus = 0xB8;
constexpr unsigned k_ibTargetHandle = 0x6F4;
constexpr unsigned k_ibCommandLine = 0x800;
constexpr unsigned k_unInjectedError = 77;

enum class EFault
{
	None,
	FailSystemDirectory,
	FailWindowsDirectory,
	FailDirectoryOpen,
	FailNtdllOpen,
	RedirectNtdll,
	FailReadFileNth,
	ShortReadFileNth,
	FailSeekNth,
	WrongFileSize,
	FailFileInfo,
	FailFirstVolume,
	FailVolumeInfo,
	FailMountPoints,
	FailOpenProcessNth,
	FailImageName,
	ShortRemoteReadNth,
	ShortWow64ReadNth,
};

EFault s_eFault = EFault::None;
unsigned s_nFaultAt = 0;
unsigned s_cCalls = 0;
DWORD s_cubFakeFileSize = 0;
std::wstring s_wstrRedirect;

bool HitFault( EFault eFault )
{
	return s_eFault == eFault && ++s_cCalls == s_nFaultAt;
}

struct Hook_t
{
	const char *m_pszLibrary;
	const char *m_pszName;
	void *m_pfnHook;
	unsigned char *m_pubTarget;
	unsigned char m_rgubSaved[5];
};

void Install( Hook_t &hook )
{
	unsigned char rgubJump[5] = { 0xE9 };
	const int nDelta = static_cast<int>( static_cast<unsigned char *>( hook.m_pfnHook ) - hook.m_pubTarget - 5 );
	std::memcpy( rgubJump + 1, &nDelta, 4 );
	DWORD unOld;
	VirtualProtect( hook.m_pubTarget, 5, PAGE_EXECUTE_READWRITE, &unOld );
	std::memcpy( hook.m_pubTarget, rgubJump, 5 );
	VirtualProtect( hook.m_pubTarget, 5, unOld, &unOld );
}

void Remove( Hook_t &hook )
{
	DWORD unOld;
	VirtualProtect( hook.m_pubTarget, 5, PAGE_EXECUTE_READWRITE, &unOld );
	std::memcpy( hook.m_pubTarget, hook.m_rgubSaved, 5 );
	VirtualProtect( hook.m_pubTarget, 5, unOld, &unOld );
}

template <typename Function_t, typename... Args_t>
auto CallReal( Hook_t &hook, Args_t... args )
{
	Remove( hook );
	const auto result = reinterpret_cast<Function_t>( hook.m_pubTarget )( args... );
	const DWORD unError = GetLastError();
	Install( hook );
	SetLastError( unError );
	return result;
}

extern Hook_t s_rgHooks[];
enum EHook
{
	k_iCreateFileW,
	k_iReadFile,
	k_iSetFilePointer,
	k_iGetFileSize,
	k_iGetSystemDirectoryW,
	k_iGetWindowsDirectoryW,
	k_iGetFileInformationByHandleEx,
	k_iFindFirstVolumeW,
	k_iGetVolumeInformationW,
	k_iGetVolumePathNames,
	k_iOpenProcess,
	k_iGetProcessImageFileNameA,
	k_iReadProcessMemory,
	k_iNtWow64ReadVirtualMemory64,
	k_cHooks,
};

HANDLE WINAPI HookCreateFileW( LPCWSTR pwszPath, DWORD unAccess, DWORD unShare, LPSECURITY_ATTRIBUTES pSecurity,
                               DWORD unDisposition, DWORD unFlags, HANDLE hTemplate )
{
	const bool bNtdll = std::wcsstr( pwszPath, L"NtDll.dll" ) != nullptr;
	if ( ( s_eFault == EFault::FailNtdllOpen && bNtdll ) || ( s_eFault == EFault::FailDirectoryOpen && !bNtdll ) )
	{
		SetLastError( k_unInjectedError );
		return INVALID_HANDLE_VALUE;
	}
	if ( s_eFault == EFault::RedirectNtdll && bNtdll )
		pwszPath = s_wstrRedirect.c_str();
	return CallReal<decltype( &CreateFileW )>( s_rgHooks[k_iCreateFileW], pwszPath, unAccess, unShare, pSecurity,
	                                           unDisposition, unFlags, hTemplate );
}

BOOL WINAPI HookReadFile( HANDLE hFile, LPVOID pBuffer, DWORD cubRead, LPDWORD pcubRead, LPOVERLAPPED pOverlapped )
{
	if ( HitFault( EFault::FailReadFileNth ) )
	{
		*pcubRead = 0;
		SetLastError( k_unInjectedError );
		return FALSE;
	}
	if ( HitFault( EFault::ShortReadFileNth ) )
		cubRead /= 2;
	return CallReal<decltype( &ReadFile )>( s_rgHooks[k_iReadFile], hFile, pBuffer, cubRead, pcubRead, pOverlapped );
}

DWORD WINAPI HookSetFilePointer( HANDLE hFile, LONG nDistance, PLONG pnHigh, DWORD unMethod )
{
	if ( HitFault( EFault::FailSeekNth ) )
	{
		SetLastError( k_unInjectedError );
		return INVALID_SET_FILE_POINTER;
	}
	return CallReal<decltype( &SetFilePointer )>( s_rgHooks[k_iSetFilePointer], hFile, nDistance, pnHigh, unMethod );
}

DWORD WINAPI HookGetFileSize( HANDLE hFile, LPDWORD punHigh )
{
	if ( s_eFault == EFault::WrongFileSize )
		return s_cubFakeFileSize;
	return CallReal<decltype( &GetFileSize )>( s_rgHooks[k_iGetFileSize], hFile, punHigh );
}

UINT WINAPI HookGetSystemDirectoryW( LPWSTR pwszBuffer, UINT cchBuffer )
{
	if ( HitFault( EFault::FailSystemDirectory ) )
	{
		SetLastError( k_unInjectedError );
		return 0;
	}
	return CallReal<decltype( &GetSystemDirectoryW )>( s_rgHooks[k_iGetSystemDirectoryW], pwszBuffer, cchBuffer );
}

UINT WINAPI HookGetWindowsDirectoryW( LPWSTR pwszBuffer, UINT cchBuffer )
{
	if ( HitFault( EFault::FailWindowsDirectory ) )
	{
		SetLastError( k_unInjectedError );
		return 0;
	}
	return CallReal<decltype( &GetWindowsDirectoryW )>( s_rgHooks[k_iGetWindowsDirectoryW], pwszBuffer, cchBuffer );
}

BOOL WINAPI HookGetFileInformationByHandleEx( HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS eClass, LPVOID pBuffer,
                                              DWORD cubBuffer )
{
	if ( s_eFault == EFault::FailFileInfo )
	{
		SetLastError( k_unInjectedError );
		return FALSE;
	}
	return CallReal<decltype( &GetFileInformationByHandleEx )>( s_rgHooks[k_iGetFileInformationByHandleEx], hFile,
	                                                            eClass, pBuffer, cubBuffer );
}

HANDLE WINAPI HookFindFirstVolumeW( LPWSTR pwszVolume, DWORD cchVolume )
{
	if ( s_eFault == EFault::FailFirstVolume )
	{
		SetLastError( k_unInjectedError );
		return INVALID_HANDLE_VALUE;
	}
	return CallReal<decltype( &FindFirstVolumeW )>( s_rgHooks[k_iFindFirstVolumeW], pwszVolume, cchVolume );
}

BOOL WINAPI HookGetVolumeInformationW( LPCWSTR pwszRoot, LPWSTR pwszLabel, DWORD cchLabel, LPDWORD punSerial,
                                       LPDWORD pcchComponent, LPDWORD punFlags, LPWSTR pwszFileSystem,
                                       DWORD cchFileSystem )
{
	if ( s_eFault == EFault::FailVolumeInfo )
	{
		SetLastError( k_unInjectedError );
		return FALSE;
	}
	return CallReal<decltype( &GetVolumeInformationW )>( s_rgHooks[k_iGetVolumeInformationW], pwszRoot, pwszLabel,
	                                                     cchLabel, punSerial, pcchComponent, punFlags, pwszFileSystem,
	                                                     cchFileSystem );
}

BOOL WINAPI HookGetVolumePathNames( LPCWSTR pwszVolume, LPWCH pwszPaths, DWORD cchPaths, PDWORD pcchReturned )
{
	if ( s_eFault == EFault::FailMountPoints )
	{
		SetLastError( k_unInjectedError );
		return FALSE;
	}
	return CallReal<decltype( &GetVolumePathNamesForVolumeNameW )>( s_rgHooks[k_iGetVolumePathNames], pwszVolume,
	                                                                pwszPaths, cchPaths, pcchReturned );
}

HANDLE WINAPI HookOpenProcess( DWORD unAccess, BOOL bInherit, DWORD unPid )
{
	if ( HitFault( EFault::FailOpenProcessNth ) )
	{
		SetLastError( k_unInjectedError );
		return nullptr;
	}
	return CallReal<decltype( &OpenProcess )>( s_rgHooks[k_iOpenProcess], unAccess, bInherit, unPid );
}

DWORD WINAPI HookGetProcessImageFileNameA( HANDLE hProcess, LPSTR pszName, DWORD cchName )
{
	if ( s_eFault == EFault::FailImageName )
	{
		SetLastError( k_unInjectedError );
		return 0;
	}
	using Pfn_t = DWORD( WINAPI * )( HANDLE, LPSTR, DWORD );
	return CallReal<Pfn_t>( s_rgHooks[k_iGetProcessImageFileNameA], hProcess, pszName, cchName );
}

BOOL WINAPI HookReadProcessMemory( HANDLE hProcess, LPCVOID pAddress, LPVOID pBuffer, SIZE_T cubRead, SIZE_T *pcubRead )
{
	if ( HitFault( EFault::ShortRemoteReadNth ) )
	{
		*pcubRead = 0;
		SetLastError( k_unInjectedError );
		return FALSE;
	}
	return CallReal<decltype( &ReadProcessMemory )>( s_rgHooks[k_iReadProcessMemory], hProcess, pAddress, pBuffer,
	                                                 cubRead, pcubRead );
}

LONG WINAPI HookNtWow64ReadVirtualMemory64( HANDLE hProcess, unsigned long long ulAddress, void *pBuffer,
                                            unsigned long long cubRead, unsigned long long *pcubRead )
{
	if ( HitFault( EFault::ShortWow64ReadNth ) )
	{
		*pcubRead = 0;
		return 0;
	}
	using Pfn_t = LONG( WINAPI * )( HANDLE, unsigned long long, void *, unsigned long long, unsigned long long * );
	return CallReal<Pfn_t>( s_rgHooks[k_iNtWow64ReadVirtualMemory64], hProcess, ulAddress, pBuffer, cubRead, pcubRead );
}

Hook_t s_rgHooks[k_cHooks] = {
    { "kernel32.dll", "CreateFileW", reinterpret_cast<void *>( HookCreateFileW ) },
    { "kernel32.dll", "ReadFile", reinterpret_cast<void *>( HookReadFile ) },
    { "kernel32.dll", "SetFilePointer", reinterpret_cast<void *>( HookSetFilePointer ) },
    { "kernel32.dll", "GetFileSize", reinterpret_cast<void *>( HookGetFileSize ) },
    { "kernel32.dll", "GetSystemDirectoryW", reinterpret_cast<void *>( HookGetSystemDirectoryW ) },
    { "kernel32.dll", "GetWindowsDirectoryW", reinterpret_cast<void *>( HookGetWindowsDirectoryW ) },
    { "kernel32.dll", "GetFileInformationByHandleEx", reinterpret_cast<void *>( HookGetFileInformationByHandleEx ) },
    { "kernel32.dll", "FindFirstVolumeW", reinterpret_cast<void *>( HookFindFirstVolumeW ) },
    { "kernel32.dll", "GetVolumeInformationW", reinterpret_cast<void *>( HookGetVolumeInformationW ) },
    { "kernel32.dll", "GetVolumePathNamesForVolumeNameW", reinterpret_cast<void *>( HookGetVolumePathNames ) },
    { "kernel32.dll", "OpenProcess", reinterpret_cast<void *>( HookOpenProcess ) },
    { "psapi.dll", "GetProcessImageFileNameA", reinterpret_cast<void *>( HookGetProcessImageFileNameA ) },
    { "kernel32.dll", "ReadProcessMemory", reinterpret_cast<void *>( HookReadProcessMemory ) },
    { "ntdll.dll", "NtWow64ReadVirtualMemory64", reinterpret_cast<void *>( HookNtWow64ReadVirtualMemory64 ) },
};

Worker_t FindWorker( HMODULE hModule, unsigned unId )
{
	auto *pubBase = reinterpret_cast<unsigned char *>( hModule );
	const auto *pNt = reinterpret_cast<const IMAGE_NT_HEADERS32 *>(
	    pubBase + reinterpret_cast<const IMAGE_DOS_HEADER *>( pubBase )->e_lfanew );
	const unsigned cubImage = pNt->OptionalHeader.SizeOfImage;
	DWORD unOld;
	VirtualProtect( pubBase, cubImage, PAGE_EXECUTE_READWRITE, &unOld );
	for ( unsigned ib = 0; ib + 12 <= cubImage; ib += 4 )
	{
		const auto *punNode = reinterpret_cast<const unsigned *>( pubBase + ib );
		const unsigned unWorker = punNode[2] - static_cast<unsigned>( reinterpret_cast<UINT_PTR>( pubBase ) );
		if ( punNode[0] == unId && punNode[1] == 1 && unWorker < cubImage )
			return reinterpret_cast<Worker_t>( pubBase + unWorker );
	}
	return nullptr;
}

DWORD CallGuarded( Worker_t pfnWorker, const unsigned char *pubInput, unsigned char *pubOutput, unsigned *pcubOutput )
{
	__try
	{
		pfnWorker( pubInput, pubOutput, pcubOutput );
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		return GetExceptionCode();
	}
	return 0;
}

struct RunResult_t
{
	std::vector<unsigned char> m_rgubOutput;
	DWORD m_unException;
};

RunResult_t RunWorker( Worker_t pfnWorker, std::vector<unsigned char> input )
{
	RunResult_t result{ std::vector<unsigned char>( k_cubAllocated, 0xCC ), 0 };
	unsigned cubOutput = k_cubAllocated;
	s_cCalls = 0;
	for ( Hook_t &hook : s_rgHooks )
		Install( hook );
	result.m_unException = CallGuarded( pfnWorker, input.data(), result.m_rgubOutput.data(), &cubOutput );
	for ( Hook_t &hook : s_rgHooks )
		Remove( hook );
	result.m_rgubOutput.resize( cubOutput );
	return result;
}

unsigned ReadU32( const std::vector<unsigned char> &bytes, unsigned ib, unsigned unKey )
{
	unsigned unValue;
	std::memcpy( &unValue, bytes.data() + ib, 4 );
	return unValue ^ unKey;
}

unsigned long long ReadU64( const std::vector<unsigned char> &bytes, unsigned ib, unsigned unKey )
{
	return ( static_cast<unsigned long long>( ReadU32( bytes, ib + 4, unKey ) ) << 32 ) | ReadU32( bytes, ib, unKey );
}

void WriteFileBytes( const std::wstring &wstrPath, const std::vector<unsigned char> &bytes )
{
	std::ofstream file( wstrPath, std::ios::binary );
	file.write( reinterpret_cast<const char *>( bytes.data() ), static_cast<std::streamsize>( bytes.size() ) );
}

std::vector<unsigned char> ReadFileBytes( const std::wstring &wstrPath )
{
	std::ifstream file( wstrPath, std::ios::binary );
	return { std::istreambuf_iterator<char>( file ), {} };
}

unsigned RvaToOffset( const std::vector<unsigned char> &image, unsigned unRva )
{
	const auto *pNt = reinterpret_cast<const IMAGE_NT_HEADERS *>(
	    image.data() + reinterpret_cast<const IMAGE_DOS_HEADER *>( image.data() )->e_lfanew );
	const IMAGE_SECTION_HEADER *pSection = IMAGE_FIRST_SECTION( pNt );
	for ( unsigned i = 0; i < pNt->FileHeader.NumberOfSections; ++i )
	{
		if ( unRva >= pSection[i].VirtualAddress && unRva < pSection[i].VirtualAddress + pSection[i].SizeOfRawData )
			return unRva - pSection[i].VirtualAddress + pSection[i].PointerToRawData;
	}
	return 0;
}

// The export directory of a 64 bit image, the one the worker reads.
IMAGE_EXPORT_DIRECTORY *ExportsOf( std::vector<unsigned char> &image )
{
	const auto *pNt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(
	    image.data() + reinterpret_cast<const IMAGE_DOS_HEADER *>( image.data() )->e_lfanew );
	const unsigned ib =
	    RvaToOffset( image, pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
	return reinterpret_cast<IMAGE_EXPORT_DIRECTORY *>( image.data() + ib );
}

HANDLE SpawnSleeper( const wchar_t *pwszCmd, DWORD *punPid )
{
	std::wstring wstrLine = std::wstring( pwszCmd ) + L" /c ping -n 300 127.0.0.1 >nul";
	STARTUPINFOW startup{};
	startup.cb = sizeof( startup );
	PROCESS_INFORMATION info{};
	PVOID pOld = nullptr;
	Wow64DisableWow64FsRedirection( &pOld );
	const BOOL bOk = CreateProcessW( pwszCmd, wstrLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
	                                 nullptr, &startup, &info );
	Wow64RevertWow64FsRedirection( pOld );
	if ( !bOk )
		return nullptr;
	CloseHandle( info.hThread );
	*punPid = info.dwProcessId;
	Sleep( 500 );
	return info.hProcess;
}

struct Scenario_t
{
	std::wstring m_wstrName;
	EFault m_eFault;
	unsigned m_nFaultAt;
	unsigned m_unPid;
	std::wstring m_wstrRedirect;
	DWORD m_cubFakeFileSize;
};

std::string Narrow( const std::wstring &wstr )
{
	std::string str;
	for ( const wchar_t wch : wstr )
		str.push_back( static_cast<char>( wch ) );
	return str;
}

} // namespace

int wmain( int argc, wchar_t **argv )
{
	if ( argc != 4 )
		return 2;

	std::vector<unsigned char> input = ReadFileBytes( argv[3] );
	if ( input.size() < 0xA0 )
		return 3;

	HMODULE hOriginal = LoadLibraryW( argv[1] );
	HMODULE hRebuild = LoadLibraryW( argv[2] );
	if ( !hOriginal || !hRebuild )
		return 4;

	const Worker_t pfnOriginal = FindWorker( hOriginal, 0x0F8083A0 );
	const Worker_t pfnRebuild = FindWorker( hRebuild, 0x0F8083A0 );
	if ( !pfnOriginal || !pfnRebuild || FindWorker( hRebuild, 0x0C2232C2 ) != pfnRebuild )
		return 5;

	for ( Hook_t &hook : s_rgHooks )
	{
		hook.m_pubTarget =
		    reinterpret_cast<unsigned char *>( GetProcAddress( LoadLibraryA( hook.m_pszLibrary ), hook.m_pszName ) );
		if ( !hook.m_pubTarget )
			return 6;
		std::memcpy( hook.m_rgubSaved, hook.m_pubTarget, 5 );
	}

	wchar_t wszTemp[MAX_PATH];
	GetTempPathW( MAX_PATH, wszTemp );
	const std::wstring wstrTemp =
	    std::wstring( wszTemp ) + L"si_parity_" + std::to_wstring( GetCurrentProcessId() ) + L"_";

	PVOID pOldRedirection = nullptr;
	Wow64DisableWow64FsRedirection( &pOldRedirection );
	const std::vector<unsigned char> ntdll64 = ReadFileBytes( L"C:\\Windows\\System32\\ntdll.dll" );
	Wow64RevertWow64FsRedirection( pOldRedirection );
	if ( ntdll64.size() < 0x10000 )
		return 7;

	const std::wstring wstrText = wstrTemp + L"text.bin";
	WriteFileBytes( wstrText, { 'h', 'e', 'l', 'l', 'o' } );

	const std::wstring wstrEmpty = wstrTemp + L"empty.bin";
	WriteFileBytes( wstrEmpty, {} );

	std::vector<unsigned char> badPe( ntdll64.begin(), ntdll64.begin() + 0x1000 );
	badPe[reinterpret_cast<const IMAGE_DOS_HEADER *>( badPe.data() )->e_lfanew] ^= 0xFF;
	const std::wstring wstrBadPe = wstrTemp + L"badpe.bin";
	WriteFileBytes( wstrBadPe, badPe );

	std::vector<unsigned char> truncated( ntdll64.begin(), ntdll64.begin() + 0x400 );
	const std::wstring wstrTruncatedHeaders = wstrTemp + L"trunc_headers.bin";
	WriteFileBytes( wstrTruncatedHeaders, truncated );

	std::vector<unsigned char> truncatedBody( ntdll64.begin(), ntdll64.begin() + ntdll64.size() / 2 );
	const std::wstring wstrTruncatedBody = wstrTemp + L"trunc_body.bin";
	WriteFileBytes( wstrTruncatedBody, truncatedBody );

	std::vector<unsigned char> overlay = ntdll64;
	overlay.resize( overlay.size() + 0x1234, 0x5A );
	const std::wstring wstrOverlay = wstrTemp + L"overlay.bin";
	WriteFileBytes( wstrOverlay, overlay );

	std::vector<unsigned char> moreNames = ntdll64;
	ExportsOf( moreNames )->NumberOfNames = ExportsOf( moreNames )->NumberOfFunctions + 1;
	const std::wstring wstrMoreNames = wstrTemp + L"more_names.bin";
	WriteFileBytes( wstrMoreNames, moreNames );

	std::vector<unsigned char> noFunctions = ntdll64;
	ExportsOf( noFunctions )->NumberOfFunctions = 0;
	const std::wstring wstrNoFunctions = wstrTemp + L"no_functions.bin";
	WriteFileBytes( wstrNoFunctions, noFunctions );

	std::vector<unsigned char> badMachine = ntdll64;
	reinterpret_cast<IMAGE_NT_HEADERS64 *>( badMachine.data() +
	                                        reinterpret_cast<const IMAGE_DOS_HEADER *>( badMachine.data() )->e_lfanew )
	    ->FileHeader.Machine = 0x1234;
	const std::wstring wstrBadMachine = wstrTemp + L"bad_machine.bin";
	WriteFileBytes( wstrBadMachine, badMachine );

	std::vector<unsigned char> badOptional = ntdll64;
	reinterpret_cast<IMAGE_NT_HEADERS64 *>( badOptional.data() +
	                                        reinterpret_cast<const IMAGE_DOS_HEADER *>( badOptional.data() )->e_lfanew )
	    ->FileHeader.SizeOfOptionalHeader = 100;
	const std::wstring wstrBadOptional = wstrTemp + L"bad_optional.bin";
	WriteFileBytes( wstrBadOptional, badOptional );

	std::vector<unsigned char> badStubs = ntdll64;
	{
		IMAGE_EXPORT_DIRECTORY *pExports = ExportsOf( badStubs );
		const unsigned *punFunctions = reinterpret_cast<const unsigned *>(
		    badStubs.data() + RvaToOffset( badStubs, pExports->AddressOfFunctions ) );
		for ( unsigned i = 0; i < pExports->NumberOfFunctions; ++i )
		{
			const unsigned ibStub = RvaToOffset( badStubs, punFunctions[i] );
			if ( ibStub )
				std::memset( badStubs.data() + ibStub, 0xCC, 8 );
		}
	}
	const std::wstring wstrBadStubs = wstrTemp + L"bad_stubs.bin";
	WriteFileBytes( wstrBadStubs, badStubs );

	DWORD unPidWow64 = 0;
	DWORD unPidNative = 0;
	const HANDLE hWow64 = SpawnSleeper( L"C:\\Windows\\SysWOW64\\cmd.exe", &unPidWow64 );
	const HANDLE hNative = SpawnSleeper( L"C:\\Windows\\System32\\cmd.exe", &unPidNative );
	if ( !hWow64 || !hNative )
		return 8;

	std::vector<Scenario_t> rgScenarios = {
	    { L"bootstrap_directory", EFault::FailSystemDirectory, 1, 0 },
	    { L"healthy", EFault::None, 0, 0 },
	    { L"healthy_wow64", EFault::None, 0, unPidWow64 },
	    { L"healthy_native64", EFault::None, 0, unPidNative },
	    { L"pid4", EFault::None, 0, 4 },
	    { L"pid_bad", EFault::None, 0, 0xFFFFFFFF },
	    { L"system_directory", EFault::FailSystemDirectory, 2, 0 },
	    { L"windows_directory", EFault::FailWindowsDirectory, 2, 0 },
	    { L"directory_open", EFault::FailDirectoryOpen, 0, 0 },
	    { L"ntdll_open", EFault::FailNtdllOpen, 0, 0 },
	    { L"file_info", EFault::FailFileInfo, 0, 0 },
	    { L"first_volume", EFault::FailFirstVolume, 0, 0 },
	    { L"volume_info", EFault::FailVolumeInfo, 0, 0 },
	    { L"mount_points", EFault::FailMountPoints, 0, 0 },
	    { L"image_name", EFault::FailImageName, 0, 0 },
	    { L"size_zero", EFault::WrongFileSize, 0, 0, L"", 0 },
	    { L"size_error", EFault::WrongFileSize, 0, 0, L"", INVALID_FILE_SIZE },
	    { L"size_huge", EFault::WrongFileSize, 0, 0, L"", 0x7FFFFFFF },
	    { L"ntdll32", EFault::RedirectNtdll, 0, 0, L"C:\\Windows\\SysWOW64\\ntdll.dll" },
	    { L"file_text", EFault::RedirectNtdll, 0, 0, wstrText },
	    { L"file_empty", EFault::RedirectNtdll, 0, 0, wstrEmpty },
	    { L"file_bad_pe", EFault::RedirectNtdll, 0, 0, wstrBadPe },
	    { L"file_trunc_headers", EFault::RedirectNtdll, 0, 0, wstrTruncatedHeaders },
	    { L"file_trunc_body", EFault::RedirectNtdll, 0, 0, wstrTruncatedBody },
	    { L"file_overlay", EFault::RedirectNtdll, 0, 0, wstrOverlay },
	    { L"file_more_names", EFault::RedirectNtdll, 0, 0, wstrMoreNames },
	    { L"file_no_functions", EFault::RedirectNtdll, 0, 0, wstrNoFunctions },
	    { L"file_bad_machine", EFault::RedirectNtdll, 0, 0, wstrBadMachine },
	    { L"file_bad_optional", EFault::RedirectNtdll, 0, 0, wstrBadOptional },
	    { L"file_bad_stubs", EFault::RedirectNtdll, 0, 0, wstrBadStubs },
	    { L"file_no_exports", EFault::RedirectNtdll, 0, 0, argv[0] },
	};
	for ( const unsigned nAt :
	      { 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 10u, 15u, 25u, 50u, 100u, 200u, 400u, 800u, 1600u, 3200u } )
	{
		rgScenarios.push_back( { L"readfile_fail_" + std::to_wstring( nAt ), EFault::FailReadFileNth, nAt, 0 } );
		rgScenarios.push_back( { L"readfile_short_" + std::to_wstring( nAt ), EFault::ShortReadFileNth, nAt, 0 } );
		rgScenarios.push_back( { L"seek_fail_" + std::to_wstring( nAt ), EFault::FailSeekNth, nAt, 0 } );
	}
	for ( unsigned nAt = 1; nAt <= 4; ++nAt )
		rgScenarios.push_back(
		    { L"open_wow64_" + std::to_wstring( nAt ), EFault::FailOpenProcessNth, nAt, unPidWow64 } );
	for ( unsigned nAt = 1; nAt <= 8; ++nAt )
		rgScenarios.push_back(
		    { L"remote_read_" + std::to_wstring( nAt ), EFault::ShortRemoteReadNth, nAt, unPidWow64 } );
	for ( unsigned nAt = 1; nAt <= 8; ++nAt )
		rgScenarios.push_back(
		    { L"wow64_read_" + std::to_wstring( nAt ), EFault::ShortWow64ReadNth, nAt, unPidNative } );

	const unsigned unKey = *reinterpret_cast<const unsigned *>( input.data() + k_ibXorKey );
	int cFailures = 0;
	for ( const Scenario_t &scenario : rgScenarios )
	{
		s_eFault = scenario.m_eFault;
		s_nFaultAt = scenario.m_nFaultAt;
		s_wstrRedirect = scenario.m_wstrRedirect;
		s_cubFakeFileSize = scenario.m_cubFakeFileSize;

		std::vector<unsigned char> caseInput = input;
		std::memcpy( caseInput.data() + k_ibTargetPid, &scenario.m_unPid, 4 );

		const RunResult_t resultBefore = RunWorker( pfnOriginal, caseInput );
		const RunResult_t resultRebuilt = RunWorker( pfnRebuild, caseInput );
		const RunResult_t resultAfter = RunWorker( pfnOriginal, caseInput );
		const std::vector<unsigned char> &before = resultBefore.m_rgubOutput;
		const std::vector<unsigned char> &rebuilt = resultRebuilt.m_rgubOutput;
		const std::vector<unsigned char> &after = resultAfter.m_rgubOutput;

		const bool bCrashed = resultBefore.m_unException || resultRebuilt.m_unException || resultAfter.m_unException;
		bool bOk = before.size() == k_cubWritten && rebuilt.size() == k_cubWritten && after.size() == k_cubWritten &&
		           resultBefore.m_unException == resultRebuilt.m_unException &&
		           resultBefore.m_unException == resultAfter.m_unException;
		unsigned cReal = 0;
		unsigned ibFirst = 0;
		if ( bOk && !bCrashed )
		{
			for ( unsigned ib = 0; ib < k_cubWritten; ++ib )
			{
				if ( before[ib] != rebuilt[ib] && before[ib] == after[ib] )
				{
					const bool bTimes = ib >= k_ibSystemTimeStart && ib < k_ibTimesEnd;
					const bool bHandle = ib >= k_ibTargetHandle && ib < k_ibTargetHandle + 4;
					if ( bTimes || bHandle )
						continue;
					if ( !cReal )
						ibFirst = ib;
					++cReal;
				}
			}

			const auto bTimeBetween = [&]( unsigned ib )
			{
				const unsigned long long ulLow = ReadU64( before, ib, unKey );
				const unsigned long long ulHigh = ReadU64( after, ib, unKey );
				const unsigned long long ulValue = ReadU64( rebuilt, ib, unKey );
				return !ulLow || ( ulLow <= ulValue && ulValue <= ulHigh );
			};
			const auto bTickBetween = [&]( unsigned ib )
			{
				const unsigned unLow = ReadU32( before, ib, unKey );
				const unsigned unHigh = ReadU32( after, ib, unKey );
				const unsigned unValue = ReadU32( rebuilt, ib, unKey );
				return !unLow || ( unLow <= unValue && unValue <= unHigh );
			};
			const bool bTimesOk = bTimeBetween( k_ibSystemTimeStart ) && bTimeBetween( k_ibSystemTimeEnd ) &&
			                      bTimeBetween( k_ibCurrentTime ) && bTickBetween( k_ibTickStart ) &&
			                      bTickBetween( k_ibTickEnd );
			const unsigned hBefore = ReadU32( before, k_ibTargetHandle, unKey );
			const unsigned hRebuilt = ReadU32( rebuilt, k_ibTargetHandle, unKey );
			const bool bHandleOk = ( hBefore != 0 ) == ( hRebuilt != 0 ) && hRebuilt < 0x10000;
			bOk = !cReal && bTimesOk && bHandleOk;
			if ( !bTimesOk || !bHandleOk )
				std::printf( "     times=%d handle=%d\n", bTimesOk, bHandleOk );
		}

		cFailures += !bOk;
		if ( bCrashed )
		{
			std::printf( "%-4s %-22s exception original=0x%08x rebuild=0x%08x\n", bOk ? "ok" : "FAIL",
			             Narrow( scenario.m_wstrName ).c_str(), static_cast<unsigned>( resultBefore.m_unException ),
			             static_cast<unsigned>( resultRebuilt.m_unException ) );
		}
		else
		{
			std::printf( "%-4s %-22s status=%u ntdll=%u cmd=%c real=%u first=0x%x\n", bOk ? "ok" : "FAIL",
			             Narrow( scenario.m_wstrName ).c_str(), ReadU32( rebuilt, k_ibStatus, unKey ),
			             ReadU32( rebuilt, k_ibNtdllStatus, unKey ),
			             ( rebuilt[k_ibCommandLine] ^ static_cast<unsigned char>( unKey ) ) ? 'y' : 'n', cReal,
			             ibFirst );
		}
		std::fflush( stdout );
	}

	TerminateProcess( hWow64, 0 );
	TerminateProcess( hNative, 0 );
	CloseHandle( hWow64 );
	CloseHandle( hNative );
	for ( const std::wstring *pwstrPath :
	      { &wstrText, &wstrEmpty, &wstrBadPe, &wstrTruncatedHeaders, &wstrTruncatedBody, &wstrOverlay, &wstrMoreNames,
	        &wstrNoFunctions, &wstrBadMachine, &wstrBadOptional, &wstrBadStubs } )
		DeleteFileW( pwstrPath->c_str() );

	std::printf( "scenarios=%u failures=%d\n", static_cast<unsigned>( rgScenarios.size() ), cFailures );
	return cFailures ? 1 : 0;
}
