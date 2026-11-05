#include "../internal/types.hpp"
#include <windows.h>
#include <array>
#include <vector>
#include <string>
#include <fstream>
#include <cstdio>
#include <cstring>

using namespace vac;
using namespace vac::workers::shared_section;
using Worker = int( __cdecl * )( const u8 *, u8 *, u32 * );
struct Row
{
	UNICODE_STRING name, type;
};
struct Scenario
{
	int resolve = 0;
	bool load = true, open = true, map = true, tree = false, grow = false, section = true, directory = true;
	u32 openError = 2;
};
static Scenario scenario;
static SystemImports_t apis{};
static u8 *original;
static std::array<u8, 4096> contents;
static std::wstring openedName, wantedName;
static u32 error = 77;
static bool grown = false;
static unsigned cases = 0, failures = 0;
static HMODULE WINAPI load( LPCSTR, HANDLE, DWORD )
{
	return scenario.load ? reinterpret_cast<HMODULE>( 0x500 ) : nullptr;
}
static DWORD WINAPI lastError()
{
	return error;
}
static BOOL WINAPI close( HANDLE )
{
	return TRUE;
}
static BOOL WINAPI unload( HMODULE )
{
	return TRUE;
}
static HANDLE WINAPI openMapping( DWORD, BOOL, LPCWSTR name )
{
	openedName = name;
	if ( scenario.open )
		return reinterpret_cast<HANDLE>( 0x20 );
	error = scenario.openError;
	return nullptr;
}
static LPVOID WINAPI mapView( HANDLE, DWORD, DWORD, DWORD, SIZE_T )
{
	if ( scenario.map )
		return contents.data();
	error = 88;
	return nullptr;
}
static BOOL WINAPI unmap( LPCVOID )
{
	return TRUE;
}
static FARPROC WINAPI resolve( HMODULE, LPCSTR name )
{
	if ( !std::strcmp( name, "OpenFileMappingW" ) )
		return scenario.resolve == 1 ? nullptr : reinterpret_cast<FARPROC>( openMapping );
	if ( !std::strcmp( name, "MapViewOfFile" ) )
		return scenario.resolve == 2 ? nullptr : reinterpret_cast<FARPROC>( mapView );
	if ( !std::strcmp( name, "UnmapViewOfFile" ) )
		return scenario.resolve == 3 ? nullptr : reinterpret_cast<FARPROC>( unmap );
	return nullptr;
}
static NTSTATUS WINAPI openDirectory( PHANDLE handle, ACCESS_MASK, POBJECT_ATTRIBUTES a )
{
	if ( !scenario.directory )
		return static_cast<NTSTATUS>( 0xC0000022 );
	*handle = a->RootDirectory ? reinterpret_cast<HANDLE>( 0x11 ) : reinterpret_cast<HANDLE>( 0x10 );
	return 0;
}
static UNICODE_STRING str( const wchar_t *p )
{
	USHORT length = static_cast<USHORT>( std::wcslen( p ) * 2 );
	return { length, static_cast<USHORT>( length + 2 ), const_cast<wchar_t *>( p ) };
}
static NTSTATUS WINAPI queryDirectory( HANDLE h, void *buffer, ULONG size, BOOLEAN, BOOLEAN, PULONG context, PULONG )
{
	if ( !scenario.tree || *context )
		return static_cast<NTSTATUS>( 0x8000001A );
	if ( scenario.grow && !grown && size == 1024 )
	{
		grown = true;
		return static_cast<NTSTATUS>( 0xC0000023 );
	}
	auto *row = static_cast<Row *>( buffer );
	if ( h == reinterpret_cast<HANDLE>( 0x10 ) )
	{
		row->name = str( L"Session" );
		row->type = str( L"Directory" );
	}
	else
	{
		row->name = str( wantedName.c_str() );
		row->type = str( L"Section" );
	}
	++*context;
	return 0;
}
static NTSTATUS WINAPI openSection( PHANDLE result, ACCESS_MASK, POBJECT_ATTRIBUTES a )
{
	if ( !scenario.section || std::wcscmp( a->ObjectName->Buffer, wantedName.c_str() ) )
		return static_cast<NTSTATUS>( 0xC0000022 );
	*result = reinterpret_cast<HANDLE>( 0x20 );
	return 0;
}
static bool __fastcall boot( void * )
{
	std::memcpy( original + 0x7D00, &apis, sizeof( apis ) );
	*reinterpret_cast<const SystemImports_t **>( original + 0x6004 ) = &apis;
	*reinterpret_cast<u32 *>( original + 0x7C78 ) = 0;
	return true;
}
static void patch( void *where, const void *function )
{
	DWORD old;
	VirtualProtect( where, 5, PAGE_EXECUTE_READWRITE, &old );
	auto *p = static_cast<u8 *>( where );
	p[0] = 0xE9;
	*reinterpret_cast<i32 *>( p + 1 ) = static_cast<i32>( reinterpret_cast<const u8 *>( function ) - p - 5 );
	FlushInstructionCache( GetCurrentProcess(), where, 5 );
	VirtualProtect( where, 5, old, &old );
}
static Worker findWorker( HMODULE dll )
{
	auto *base = reinterpret_cast<u8 *>( dll );
	auto *nt = reinterpret_cast<IMAGE_NT_HEADERS *>( base + reinterpret_cast<IMAGE_DOS_HEADER *>( base )->e_lfanew );
	const auto *sections = IMAGE_FIRST_SECTION( nt );
	for ( unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i )
	{
		if ( sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE )
			continue;
		for ( unsigned j = 0; j + 48 <= sections[i].Misc.VirtualSize; j += 4 )
		{
			auto *p = base + sections[i].VirtualAddress + j;
			if ( *reinterpret_cast<u32 *>( p + 4 ) == k_unModuleId && *reinterpret_cast<u32 *>( p + 8 ) == 1 )
			{
				auto fn = *reinterpret_cast<Worker *>( p + 12 );
				if ( reinterpret_cast<u8 *>( fn ) >= base &&
				     reinterpret_cast<u8 *>( fn ) < base + nt->OptionalHeader.SizeOfImage )
					return fn;
			}
		}
	}
	return nullptr;
}
static int live( const char *dllPath, const char *seedPath )
{
	HMODULE dll = LoadLibraryA( dllPath );
	if ( !dll )
		return 4;
	Worker a = reinterpret_cast<Worker>( original + 0x2DE1 ), b = findWorker( dll );
	if ( !b )
		return 5;
	Input_t input{};
	std::ifstream seed( seedPath, std::ios::binary );
	seed.read( reinterpret_cast<char *>( &input ), 160 );
	if ( !seed )
		return 6;
	unsigned failed = 0, n = 0;
	for ( u32 cap : { 0u, 1u, 4095u, 4096u } )
	{
		input.m_unIdentifier = static_cast<u32>( GetCurrentProcessId() ) ^ 0xA5000000u ^ cap;
		wchar_t name[128]{};
		FormatMappingName( input.m_unIdentifier, name );
		HANDLE file = CreateFileMappingW( INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 4096, name );
		if ( !file || GetLastError() == ERROR_ALREADY_EXISTS )
		{
			if ( file )
				CloseHandle( file );
			return 7;
		}
		auto *view = static_cast<u8 *>( MapViewOfFile( file, FILE_MAP_ALL_ACCESS, 0, 0, 4096 ) );
		if ( !view )
			return 8;
		for ( unsigned i = 0; i < 4096; ++i )
			view[i] = static_cast<u8>( ( i * 73 + cap + 19 ) ^ ( i >> 3 ) );
		std::array<u8, 4096> left{}, right{};
		u32 sa = cap, sb = cap;
		int ra = a( reinterpret_cast<u8 *>( &input ), left.data(), &sa ),
		    rb = b( reinterpret_cast<u8 *>( &input ), right.data(), &sb );
		bool ok = ra == rb && sa == sb && sa == 4096 && left == right &&
		          reinterpret_cast<Report_t *>( left.data() )->m_eStatus == EScanStatus::Ok;
		std::printf( "LIVE cap=%u %s\n", cap, ok ? "OK" : "DIFF" );
		++n;
		if ( !ok )
			++failed;
		UnmapViewOfFile( view );
		CloseHandle( file );
	}
	std::printf( "LIVE RESULT %u cases, %u failures\n", n, failed );
	return failed ? 1 : 0;
}
int main( int argc, char **argv )
{
	if ( argc != 2 && argc != 5 )
		return 2;
	original = reinterpret_cast<u8 *>( LoadLibraryA( argv[1] ) );
	if ( !original )
		return 3;
	if ( argc == 5 && !std::strcmp( argv[2], "--live" ) )
		return live( argv[3], argv[4] );
	patch( original + 0x4BF0, boot );
	apis.LoadLibraryExA = load;
	apis.GetProcAddress = resolve;
	apis.GetLastError = lastError;
	apis.FreeLibrary = unload;
	apis.CloseHandle = close;
	apis.NtOpenDirectoryObject = openDirectory;
	apis.NtQueryDirectoryObject = queryDirectory;
	apis.NtOpenSection = openSection;
	apis.HeapAlloc = HeapAlloc;
	apis.HeapFree = HeapFree;
	apis.GetProcessHeap = GetProcessHeap;
	auto worker = reinterpret_cast<Worker>( original + 0x2DE1 );
	for ( u32 id : { 0u, 1u, 0x01020304u, 0x80FFAA55u, 0xFFFFFFFFu } )
	{
		for ( unsigned kind = 0; kind < 11; ++kind )
		{
			scenario = {};
			if ( kind == 1 )
				scenario.load = false;
			if ( kind >= 2 && kind <= 4 )
				scenario.resolve = kind - 1;
			if ( kind == 5 )
			{
				scenario.open = false;
				scenario.openError = 5;
			}
			if ( kind == 6 )
				scenario.open = false;
			if ( kind == 7 )
				scenario.map = false;
			if ( kind >= 8 )
			{
				scenario.open = false;
				scenario.tree = true;
			}
			if ( kind == 9 )
				scenario.grow = true;
			if ( kind == 10 )
				scenario.section = false;
			Input_t in{};
			in.m_unIdentifier = id;
			wchar_t name[128]{};
			FormatMappingName( id, name );
			wantedName = name;
			for ( unsigned i = 0; i < 4096; ++i )
				contents[i] = static_cast<u8>( i * 31 + kind + ( id >> 24 ) );
			std::array<u8, 4096> expected{}, actual{};
			u32 size = 0;
			error = 77;
			grown = false;
			openedName.clear();
			int ret = worker( reinterpret_cast<u8 *>( &in ), expected.data(), &size );
			std::wstring originalName = openedName;
			error = 77;
			grown = false;
			openedName.clear();
			auto &out = *reinterpret_cast<Report_t *>( actual.data() );
			out.m_unMagic = k_unReportMagic;
			ReadMapping( in, out, &apis );
			bool equal = ret == 0 && size == 4096 && expected == actual && openedName == originalName;
			++cases;
			if ( !equal )
			{
				++failures;
				std::printf( "DIFF %08x case=%u\n", id, kind );
				for ( unsigned i = 0, shown = 0; i < 4096 && shown < 12; ++i )
					if ( expected[i] != actual[i] )
					{
						std::printf( " +%x %02x/%02x\n", i, expected[i], actual[i] );
						++shown;
					}
			}
			else
				std::printf( "OK %08x case=%u\n", id, kind );
		}
	}
	std::printf( "RESULT %u cases, %u failures\n", cases, failures );
	return failures ? 1 : 0;
}
