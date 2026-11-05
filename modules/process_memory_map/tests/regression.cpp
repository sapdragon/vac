// Native checks of the rewrite. Without arguments it runs the unit checks. The two target modes keep a process alive
// for the differential runs: analysis/8d88e017/compare_live.py --pressure and tests/compare_crafted.py.
#include "internal/pe_reader.hpp"
#include "internal/process_context.hpp"
#include "internal/report_builder.hpp"

#include "crt/intrinsics.hpp"
#include "crypto/hash/md5.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace vac;
using namespace vac::workers::process_memory_map;

namespace
{

int g_cFailures = 0;

void Check( bool bOk, const char *pszMessage )
{
	if ( !bOk )
	{
		++g_cFailures;
		std::printf( "FAIL: %s\n", pszMessage );
	}
}

const MEMORY_BASIC_INFORMATION32 g_rgRegions[] = {
    { 0x10000, 0x10000, 0, 0x1000, MEM_RESERVE, 0, MEM_PRIVATE },
    { 0x11000, 0x10000, 0, 0x1000, MEM_COMMIT, PAGE_READONLY, MEM_PRIVATE },
    { 0x12000, 0x10000, 0, 0x2000, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE },
    { 0x14000, 0x10000, 0, 0x1000, MEM_RESERVE, 0, MEM_PRIVATE },
    { 0x15000, 0x10000, 0, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE },
    { 0x16000, 0x16000, 0, 0x1000, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE },
};

NTSTATUS NTAPI QueryMock( HANDLE, void *pAddress, DWORD, void *pOutput, ULONG cubOutput, PULONG pcubReturned )
{
	const auto ulAddress = reinterpret_cast<uptr>( pAddress );
	for ( const auto &region : g_rgRegions )
	{
		if ( ulAddress >= region.BaseAddress && ulAddress < region.BaseAddress + region.RegionSize &&
		     cubOutput == sizeof( region ) )
		{
			std::memcpy( pOutput, &region, sizeof( region ) );
			*pcubReturned = sizeof( region );
			return 0;
		}
	}
	*pcubReturned = 0;
	return static_cast<NTSTATUS>( 0xC000000Du );
}

void CheckAllocationWalk()
{
	SystemImports_t imports{};
	imports.NtQueryVirtualMemory = QueryMock;
	imports.GetLastError = ::GetLastError;

	AllocationWalk_t walk{};
	walk.m_ulCursor = 0x10000;
	Check( WalkAllocation( &imports, reinterpret_cast<HANDLE>( 1 ), walk ), "aggregate allocation" );
	Check( walk.m_ulFirstCommitted == 0x11000 && walk.m_ulCursor == 0x16000, "committed base and next allocation" );
	Check( walk.m_cubCommitPrefix == 0x3000 && walk.m_cubTotal == 0x5000, "prefix and total span" );
	Check( walk.m_cRegions == 5 && walk.m_unProtectUnion == 0x26 && walk.m_unExecuteProtectUnion == 0x20,
	       "region count and protection union" );

	SetLastError( 1234 );
	AllocationWalk_t failed{};
	failed.m_ulCursor = 0xFFFFF000;
	Check( !WalkAllocation( &imports, reinterpret_cast<HANDLE>( 1 ), failed ), "invalid query fails" );
	Check( GetLastError() == 1234 && failed.m_unLastError == 1234, "NT query failure keeps the Win32 error" );
}

int g_nCaptureStage = 0;

NTSTATUS NTAPI QueryProcessMock( HANDLE, PROCESSINFOCLASS eClass, void *pOutput, ULONG, PULONG pcubReturned )
{
	if ( eClass != ProcessBasicInformation )
	{
		*pcubReturned = 0;
		return 0;
	}
	auto *pBasic = static_cast<nt::ProcessBasicInformation32_t *>( pOutput );
	std::memset( pBasic, 0, sizeof( *pBasic ) );
	*pcubReturned = g_nCaptureStage ? sizeof( *pBasic ) : 0;
	if ( g_nCaptureStage >= 2 )
		pBasic->m_ulPebBaseAddress = 0x1000;
	return 0;
}

constexpr wchar_t k_wszLdrName[] = L"C:\\mock\\one.dll";

BOOL WINAPI ReadMock( HANDLE, LPCVOID pAddress, LPVOID pOutput, SIZE_T cubOutput, SIZE_T *pcubRead )
{
	*pcubRead = 0;
	const auto ulAddress = reinterpret_cast<uptr>( pAddress );
	if ( ulAddress == 0x1000 && g_nCaptureStage >= 3 && cubOutput == sizeof( nt::Peb32_t ) )
	{
		std::memset( pOutput, 0, cubOutput );
		static_cast<nt::Peb32_t *>( pOutput )->m_ulLdr = 0x2000;
	}
	else if ( ulAddress == 0x2000 && g_nCaptureStage >= 4 && cubOutput == nt::Arch32_t::k_cubPebLdrSnapshot )
	{
		std::memset( pOutput, 0, cubOutput );
		if ( g_nCaptureStage >= 5 )
			static_cast<nt::PebLdrData32_t *>( pOutput )->m_InLoadOrderModuleList.m_ulFlink = 0x3000;
	}
	else if ( ulAddress == 0x3000 && g_nCaptureStage >= 6 && cubOutput == nt::Arch32_t::k_cubLdrEntrySnapshot )
	{
		auto *pEntry = static_cast<nt::LdrDataTableEntry32_t *>( pOutput );
		std::memset( pEntry, 0, cubOutput );
		pEntry->m_InLoadOrderLinks.m_ulFlink = 0x4000;
		pEntry->m_ulDllBase = 0x90000000;
		pEntry->m_cubSizeOfImage = 0x5000;
		pEntry->m_FullDllName.m_cubLength = sizeof( k_wszLdrName ) - sizeof( wchar_t );
		pEntry->m_FullDllName.m_ulBuffer = 0x5000;
	}
	else if ( ulAddress == 0x4000 && g_nCaptureStage >= 6 && cubOutput == nt::Arch32_t::k_cubLdrEntrySnapshot )
	{
		std::memset( pOutput, 0, cubOutput ); // The list head, no DllBase.
	}
	else if ( ulAddress == 0x5000 && g_nCaptureStage >= 6 )
	{
		std::memcpy( pOutput, k_wszLdrName, cubOutput );
	}
	else
	{
		return FALSE;
	}
	*pcubRead = cubOutput;
	return TRUE;
}

HANDLE WINAPI OpenMock( DWORD, BOOL, DWORD )
{
	return reinterpret_cast<HANDLE>( 1 );
}
BOOL WINAPI CloseMock( HANDLE )
{
	return TRUE;
}
BOOL WINAPI TimesMock( HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME )
{
	return FALSE;
}

void CheckLdrCapture()
{
	SystemImports_t imports{};
	imports.OpenProcess = OpenMock;
	imports.CloseHandle = CloseMock;
	imports.GetProcessTimes = TimesMock;
	imports.GetLastError = ::GetLastError;
	imports.NtQueryInformationProcess = QueryProcessMock;
	imports.ReadProcessMemory = ReadMock;

	ModuleSession_t session{};
	session.m_OsVersion.dwPlatformId = 2;
	session.m_OsVersion.dwMajorVersion = 10;

	constexpr u32 k_unOpenFlags = 0x5;
	const EScanStatus rgeStatus[] = { EScanStatus::BasicInfoFailed,   EScanStatus::NoPeb,
	                                  EScanStatus::PebReadFailed,     EScanStatus::ProcessReadFailed,
	                                  EScanStatus::ProcessReadFailed, EScanStatus::ProcessReadFailed };
	const u32 rgunFlags[] = { 0, 8, 0x18, 0x20038, 0xC0078, 0x4C0078 };
	for ( g_nCaptureStage = 0; g_nCaptureStage < 6; ++g_nCaptureStage )
	{
		ProcessContext_t context{};
		const EScanStatus eStatus = OpenProcessAndCaptureLdr( context, 1234, &imports, &session );
		Check( eStatus == rgeStatus[g_nCaptureStage], "LDR failure status" );
		Check( static_cast<u32>( context.m_eCaptureFlags ) == ( rgunFlags[g_nCaptureStage] | k_unOpenFlags ),
		       "LDR failure capture flags" );
		Check( context.m_cModules == 0 && context.m_unLastError == 0, "LDR failure keeps zero result fields" );
	}

	g_nCaptureStage = 6;
	ProcessContext_t context{};
	context.m_hProcess = INVALID_HANDLE_VALUE;
	Check( OpenProcessAndCaptureLdr( context, 1234, &imports, &session ) == EScanStatus::Ok, "LDR capture succeeds" );
	Check( context.m_cModules == 1, "the list head is not a module" );
	Check( context.m_pModules[0].m_cubImage == 0x1000, "32-bit entries record one page, not SizeOfImage" );
	Check( context.m_pModules[0].m_ulBase == 0xFFFFFFFF90000000ull, "32-bit bases are sign extended" );
	Check( context.m_pModules[0].m_unIndex == 1, "module index starts at one" );
	Check( std::wcscmp( context.m_pModules[0].m_wszFullPath, k_wszLdrName ) == 0, "module path" );
	Check( std::wcscmp( context.m_pModules[0].m_wszBaseName, L"one.dll" ) == 0, "module base name" );
	ReleaseProcessContext( context, &imports );
}

constexpr u32 k_ibNtHeaders = 0x100;
constexpr u32 k_ibOptionalHeader = k_ibNtHeaders + 4 + sizeof( IMAGE_FILE_HEADER );
constexpr u32 k_cubHeaders = 0x400;
constexpr u32 k_unFileAlignment = 0x200;
constexpr u32 k_unSectionAlignment = 0x1000;
constexpr u32 k_unTextRva = 0x1000;
constexpr u32 k_cubText = 0x3000;

struct Reloc_t
{
	u32 m_unRva;
	u16 m_unType;
};

struct Crafted_t
{
	std::vector<u8> m_rgubFile;
	u32 m_unImageBase = 0;
};

std::vector<u8> BuildRelocationTable( const std::vector<Reloc_t> &relocs )
{
	std::vector<u8> table;
	for ( size_t i = 0; i < relocs.size(); )
	{
		const u32 unPage = relocs[i].m_unRva & 0xFFFFF000u;
		std::vector<u16> rgunEntries;
		while ( i < relocs.size() && ( relocs[i].m_unRva & 0xFFFFF000u ) == unPage )
		{
			rgunEntries.push_back( static_cast<u16>( ( relocs[i].m_unType << 12 ) | ( relocs[i].m_unRva & 0xFFF ) ) );
			++i;
		}
		if ( rgunEntries.size() & 1 )
			rgunEntries.push_back( 0 );
		const u32 cubBlock = 8 + static_cast<u32>( rgunEntries.size() ) * 2;
		table.insert( table.end(), reinterpret_cast<const u8 *>( &unPage ),
		              reinterpret_cast<const u8 *>( &unPage ) + 4 );
		table.insert( table.end(), reinterpret_cast<const u8 *>( &cubBlock ),
		              reinterpret_cast<const u8 *>( &cubBlock ) + 4 );
		table.insert( table.end(), reinterpret_cast<const u8 *>( rgunEntries.data() ),
		              reinterpret_cast<const u8 *>( rgunEntries.data() ) + rgunEntries.size() * 2 );
	}
	return table;
}

struct PeOptions_t
{
	bool m_bPe64 = false;
	u32 m_unImageBase = 0x20000000;
	const char *m_pszTextName = ".text";
	std::vector<Reloc_t> m_Relocs;
	bool m_bRelocationSection = true;
	bool m_bRelocationsInOverlay = false;
	u32 m_cubOverlay = 0;
	bool m_bValveStub = false;
	u16 m_unOptionalMagic = 0;
	u32 m_unRelocationVaOverride = 0;
	IMAGE_DATA_DIRECTORY m_Iat{};
	IMAGE_DATA_DIRECTORY m_Export{};
	u32 m_cSectionsOverride = 0xFFFF;
	bool m_bFlat = false; // Raw offsets equal the RVAs, so a flat file mapping reads like a loaded image.
};

Crafted_t BuildPe( const PeOptions_t &options )
{
	const std::vector<u8> relocations = BuildRelocationTable( options.m_Relocs );
	const u32 cubOptional = options.m_bPe64 ? sizeof( IMAGE_OPTIONAL_HEADER64 ) : sizeof( IMAGE_OPTIONAL_HEADER32 );
	const u32 cubHeaders = options.m_bFlat ? k_unSectionAlignment : k_cubHeaders;
	const u32 unFileAlignment = options.m_bFlat ? k_unSectionAlignment : k_unFileAlignment;

	std::vector<IMAGE_SECTION_HEADER> rgSections;
	IMAGE_SECTION_HEADER text{};
	std::memcpy( text.Name, options.m_pszTextName, std::strlen( options.m_pszTextName ) );
	text.Misc.VirtualSize = k_cubText;
	text.VirtualAddress = k_unTextRva;
	text.SizeOfRawData = k_cubText;
	text.PointerToRawData = cubHeaders;
	text.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
	rgSections.push_back( text );

	u32 ibRaw = cubHeaders + k_cubText;
	u32 unRva = k_unTextRva + k_cubText;
	u32 unRelocationRva = 0;
	if ( options.m_bRelocationSection && !options.m_bRelocationsInOverlay && !relocations.empty() )
	{
		IMAGE_SECTION_HEADER reloc{};
		std::memcpy( reloc.Name, ".reloc", 6 );
		reloc.Misc.VirtualSize = static_cast<u32>( relocations.size() );
		reloc.VirtualAddress = unRva;
		reloc.SizeOfRawData =
		    ( static_cast<u32>( relocations.size() ) + unFileAlignment - 1 ) & ~( unFileAlignment - 1 );
		reloc.PointerToRawData = ibRaw;
		reloc.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
		rgSections.push_back( reloc );
		unRelocationRva = unRva;
		ibRaw += reloc.SizeOfRawData;
		unRva += ( reloc.Misc.VirtualSize + k_unSectionAlignment - 1 ) & ~( k_unSectionAlignment - 1 );
	}

	const u32 cubSectionsEnd = ibRaw;
	u32 cubOverlay = options.m_cubOverlay;
	if ( options.m_bRelocationsInOverlay )
	{
		// The VA pe::AppendOverlaySection gives ".extra": right after the last section, aligned.
		const IMAGE_SECTION_HEADER &last = rgSections.back();
		unRelocationRva =
		    ( last.VirtualAddress + last.Misc.VirtualSize + k_unSectionAlignment - 1 ) & ~( k_unSectionAlignment - 1 );
		cubOverlay = static_cast<u32>( relocations.size() );
	}
	if ( options.m_unRelocationVaOverride )
		unRelocationRva = options.m_unRelocationVaOverride;

	Crafted_t crafted;
	crafted.m_unImageBase = options.m_unImageBase;
	std::vector<u8> &file = crafted.m_rgubFile;
	file.assign( cubSectionsEnd + cubOverlay, 0 );

	u32 unSeed = 0x1234567;
	for ( u32 ib = cubHeaders; ib < file.size(); ++ib )
	{
		unSeed = unSeed * 1664525u + 1013904223u;
		file[ib] = static_cast<u8>( unSeed >> 24 );
	}

	auto *pDos = reinterpret_cast<IMAGE_DOS_HEADER *>( file.data() );
	pDos->e_magic = IMAGE_DOS_SIGNATURE;
	pDos->e_lfanew = k_ibNtHeaders;
	if ( options.m_bValveStub )
	{
		const u32 rgunStub[3] = { 0x564C56, 1, 7 };
		std::memcpy( file.data() + sizeof( IMAGE_DOS_HEADER ), rgunStub, sizeof( rgunStub ) );
	}

	std::memcpy( file.data() + k_ibNtHeaders, "PE\0\0", 4 );
	auto *pFileHeader = reinterpret_cast<IMAGE_FILE_HEADER *>( file.data() + k_ibNtHeaders + 4 );
	pFileHeader->Machine = options.m_bPe64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
	pFileHeader->NumberOfSections =
	    static_cast<WORD>( options.m_cSectionsOverride != 0xFFFF ? options.m_cSectionsOverride : rgSections.size() );
	pFileHeader->SizeOfOptionalHeader = static_cast<WORD>( cubOptional );

	const auto SetOptional = [&]( auto *pOptional, u16 unMagic )
	{
		pOptional->Magic = options.m_unOptionalMagic ? options.m_unOptionalMagic : unMagic;
		pOptional->ImageBase = options.m_unImageBase;
		pOptional->SectionAlignment = k_unSectionAlignment;
		pOptional->FileAlignment = unFileAlignment;
		pOptional->SizeOfImage = 0x8000;
		pOptional->SizeOfHeaders = cubHeaders;
		pOptional->NumberOfRvaAndSizes = 16;
		pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = unRelocationRva;
		pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = static_cast<u32>( relocations.size() );
		pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = options.m_Iat;
		pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] = options.m_Export;
	};
	if ( options.m_bPe64 )
		SetOptional( reinterpret_cast<IMAGE_OPTIONAL_HEADER64 *>( file.data() + k_ibOptionalHeader ),
		             IMAGE_NT_OPTIONAL_HDR64_MAGIC );
	else
		SetOptional( reinterpret_cast<IMAGE_OPTIONAL_HEADER32 *>( file.data() + k_ibOptionalHeader ),
		             IMAGE_NT_OPTIONAL_HDR32_MAGIC );

	std::memcpy( file.data() + k_ibOptionalHeader + cubOptional, rgSections.data(),
	             rgSections.size() * sizeof( IMAGE_SECTION_HEADER ) );

	if ( !relocations.empty() )
	{
		const u32 ibTable = options.m_bRelocationsInOverlay ? cubSectionsEnd : cubHeaders + k_cubText;
		if ( options.m_bRelocationSection || options.m_bRelocationsInOverlay )
			std::memcpy( file.data() + ibTable, relocations.data(), relocations.size() );
	}
	return crafted;
}

// What the original should hash for a PE32 whose relocations are all HIGHLOW: every value in .text moved by the delta.
void ExpectedDigest( const Crafted_t &crafted, const std::vector<Reloc_t> &relocs, u8 *pubDigest )
{
	const std::vector<u8> &file = crafted.m_rgubFile;
	const auto *pFileHeader = reinterpret_cast<const IMAGE_FILE_HEADER *>( file.data() + k_ibNtHeaders + 4 );

	crypto::hash::Md5_t md5;
	md5.Update( file.data(), sizeof( IMAGE_DOS_HEADER ) );
	md5.Update( reinterpret_cast<const u8 *>( pFileHeader ), sizeof( IMAGE_FILE_HEADER ) );

	IMAGE_OPTIONAL_HEADER32 optional;
	std::memcpy( &optional, file.data() + k_ibOptionalHeader, sizeof( optional ) );
	optional.ImageBase = 0;
	md5.Update( reinterpret_cast<const u8 *>( &optional ), sizeof( optional ) );

	const auto *pSections =
	    reinterpret_cast<const IMAGE_SECTION_HEADER *>( file.data() + k_ibOptionalHeader + sizeof( optional ) );
	for ( u32 iSection = 0; iSection < pFileHeader->NumberOfSections; ++iSection )
	{
		md5.Update( pSections[iSection].Name, 8 );
		md5.Update( reinterpret_cast<const u8 *>( &pSections[iSection].VirtualAddress ), 4 );
		md5.Update( reinterpret_cast<const u8 *>( &pSections[iSection].SizeOfRawData ), 4 );
	}

	std::vector<u8> text( file.begin() + k_cubHeaders, file.begin() + k_cubHeaders + k_cubText );
	const u32 unDelta = crafted.m_unImageBase - 0x10000000u;
	for ( const Reloc_t &reloc : relocs )
	{
		u32 unValue;
		std::memcpy( &unValue, text.data() + reloc.m_unRva - k_unTextRva, 4 );
		unValue -= unDelta;
		std::memcpy( text.data() + reloc.m_unRva - k_unTextRva, &unValue, 4 );
	}
	md5.Update( text.data(), text.size() );
	md5.Final( pubDigest );
}

std::string WriteTemporaryFile( const std::vector<u8> &rgubData, const char *pszName )
{
	char szDirectory[MAX_PATH];
	GetTempPathA( MAX_PATH, szDirectory );
	const std::string path = std::string( szDirectory ) + "pmi_regression_" + pszName + ".bin";
	HANDLE hFile =
	    CreateFileA( path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr );
	DWORD cubWritten = 0;
	WriteFile( hFile, rgubData.data(), static_cast<DWORD>( rgubData.size() ), &cubWritten, nullptr );
	CloseHandle( hFile );
	return path;
}

bool HashCraftedFile( const Crafted_t &crafted, const char *pszName, u8 *pubDigest )
{
	SystemImports_t imports{};
	imports.ReadFile = ::ReadFile;
	imports.SetFilePointer = ::SetFilePointer;
	imports.GetFileSize = ::GetFileSize;
	imports.CloseHandle = ::CloseHandle;

	const std::string path = WriteTemporaryFile( crafted.m_rgubFile, pszName );
	HANDLE hFile = CreateFileA( path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
	                            FILE_ATTRIBUTE_NORMAL, nullptr );

	auto *pReader = new CPeReader( &imports );
	bool bHashed = false;
	if ( pReader->AttachFile( hFile ) && pReader->ParseFile() == EScanStatus::Ok )
		bHashed = pReader->HashImage( pubDigest );
	pReader->Release();
	pReader->CloseSource();
	delete pReader;
	DeleteFileA( path.c_str() );
	return bHashed;
}

void CheckCraftedImages()
{
	u8 rgubActual[16];
	u8 rgubExpected[16];

	// The second value starts 2 bytes before the 4 KB chunk end, the last chunk's tail runs into the next section.
	PeOptions_t crossing;
	crossing.m_Relocs = { { 0x1100, 3 }, { 0x1FFE, 3 }, { 0x2FFD, 3 }, { 0x3000, 3 } };
	const Crafted_t crossingPe = BuildPe( crossing );
	Check( HashCraftedFile( crossingPe, "crossing", rgubActual ), "relocations that cross a chunk end hash" );
	ExpectedDigest( crossingPe, crossing.m_Relocs, rgubExpected );
	Check( !std::memcmp( rgubActual, rgubExpected, 16 ), "a value that crosses a chunk end is patched whole" );

	PeOptions_t unknownType;
	unknownType.m_Relocs = { { 0x1100, 3 }, { 0x1200, 10 } };
	Check( !HashCraftedFile( BuildPe( unknownType ), "unknown", rgubActual ),
	       "an unknown relocation type fails the hash" );

	PeOptions_t absolute;
	absolute.m_Relocs = { { 0x1100, 0 }, { 0x1200, 3 } };
	const Crafted_t absolutePe = BuildPe( absolute );
	Check( HashCraftedFile( absolutePe, "absolute", rgubActual ), "IMAGE_REL_BASED_ABSOLUTE is skipped" );
	const std::vector<Reloc_t> absoluteApplied = { { 0x1200, 3 } };
	ExpectedDigest( absolutePe, absoluteApplied, rgubExpected );
	Check( !std::memcmp( rgubActual, rgubExpected, 16 ), "only the HIGHLOW value moves" );

	// Only ".extra" can place this table: the directory RVA is in no section of the file.
	PeOptions_t overlayTable;
	overlayTable.m_Relocs = { { 0x1100, 3 }, { 0x1FFE, 3 } };
	overlayTable.m_bRelocationsInOverlay = true;
	const Crafted_t overlayPe = BuildPe( overlayTable );
	Check( HashCraftedFile( overlayPe, "overlay", rgubActual ), "relocations in the overlay hash" );
	ExpectedDigest( overlayPe, overlayTable.m_Relocs, rgubExpected );
	Check( !std::memcmp( rgubActual, rgubExpected, 16 ), "the relocation table is found through .extra" );
}

void CheckEmptyCompression()
{
	auto *pBuilder = new ReportBuilder_t{};
	pBuilder->m_pubRecords = pBuilder->m_rgubRecords;
	pBuilder->m_pubHashes = pBuilder->m_rgubHashes;
	u8 rgubCompressed[16]{};
	rgubCompressed[0] = 0xFF;
	Check( CompressRecords( *pBuilder, rgubCompressed ) == 1 && pBuilder->m_cubPlain == 0 && rgubCompressed[0] == 0,
	       "an empty inventory is one zero LZ4 token" );
	delete pBuilder;
}

int RunPressureTarget( const char *pszDirectory )
{
	std::vector<HANDLE> rgFiles, rgMappings;
	std::vector<void *> rgViews;
	u32 unRandom = 0x12345678;
	for ( unsigned iFile = 0; iFile < 420; ++iFile )
	{
		char szPath[MAX_PATH];
		std::sprintf( szPath, "%s\\mapping-%08x-%08x.bin", pszDirectory, iFile, unRandom );
		HANDLE hFile = CreateFileA( szPath, GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE, FILE_SHARE_READ, nullptr,
		                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr );
		if ( hFile == INVALID_HANDLE_VALUE )
		{
			std::printf( "file: %lu\n", GetLastError() );
			return 2;
		}
		u8 rgubBytes[4096];
		for ( auto &ub : rgubBytes )
		{
			unRandom = unRandom * 1664525u + 1013904223u;
			ub = static_cast<u8>( unRandom >> 24 );
		}
		DWORD cubWritten = 0;
		if ( !WriteFile( hFile, rgubBytes, sizeof( rgubBytes ), &cubWritten, nullptr ) ||
		     cubWritten != sizeof( rgubBytes ) )
			return 2;
		HANDLE hMapping = CreateFileMappingA( hFile, nullptr, PAGE_EXECUTE_READWRITE, 0, sizeof( rgubBytes ), nullptr );
		if ( !hMapping )
		{
			std::printf( "mapping: %lu\n", GetLastError() );
			return 2;
		}
		void *pView =
		    MapViewOfFile( hMapping, FILE_MAP_READ | FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, sizeof( rgubBytes ) );
		if ( !pView )
		{
			std::printf( "view: %lu\n", GetLastError() );
			return 2;
		}
		rgFiles.push_back( hFile );
		rgMappings.push_back( hMapping );
		rgViews.push_back( pView );
	}
	std::puts( "ready" );
	std::fflush( stdout );
	Sleep( 120000 );
	for ( void *pView : rgViews )
		UnmapViewOfFile( pView );
	for ( HANDLE hMapping : rgMappings )
		CloseHandle( hMapping );
	for ( HANDLE hFile : rgFiles )
		CloseHandle( hFile );
	return 0;
}

// Maps each crafted image executable, so both workers walk onto it and hash it.
int RunCraftedTarget( const char *pszDirectory )
{
	struct Case_t
	{
		const char *m_pszName;
		Crafted_t m_Pe;
		bool m_bExclusive; // Nobody else can open the file, so the hash has to come from memory.
	};
	std::vector<Case_t> rgCases;
	const auto Add = [&]( const char *pszName, const PeOptions_t &options, bool bExclusive = false )
	{ rgCases.push_back( { pszName, BuildPe( options ), bExclusive } ); };

	PeOptions_t crossing;
	crossing.m_Relocs = { { 0x1100, 3 }, { 0x1FFE, 3 }, { 0x2FFD, 3 }, { 0x3000, 3 } };
	Add( "crossing", crossing );
	Add( "memory_crossing", crossing, true );

	PeOptions_t flatCrossing = crossing;
	flatCrossing.m_bFlat = true;
	Add( "flat_crossing", flatCrossing );
	Add( "memory_flat_crossing", flatCrossing, true );

	PeOptions_t flatUnknown;
	flatUnknown.m_bFlat = true;
	flatUnknown.m_Relocs = { { 0x1100, 3 }, { 0x1200, 10 } };
	Add( "memory_flat_unknown", flatUnknown, true );

	PeOptions_t unknownType;
	unknownType.m_Relocs = { { 0x1100, 3 }, { 0x1200, 10 } };
	Add( "unknown_type", unknownType );
	Add( "memory_unknown_type", unknownType, true );

	PeOptions_t dir64Late;
	dir64Late.m_Relocs = { { 0x1100, 3 }, { 0x3FF0, 10 } };
	Add( "unknown_type_late", dir64Late );

	PeOptions_t overlayTable;
	overlayTable.m_Relocs = { { 0x1100, 3 }, { 0x1FFE, 3 } };
	overlayTable.m_bRelocationsInOverlay = true;
	Add( "relocs_in_overlay", overlayTable );
	Add( "memory_relocs_in_overlay", overlayTable, true );

	PeOptions_t overlayOnly;
	overlayOnly.m_Relocs = { { 0x1100, 3 } };
	overlayOnly.m_cubOverlay = 0x777;
	Add( "overlay_plain", overlayOnly );

	PeOptions_t relocOutside;
	relocOutside.m_Relocs = { { 0x1100, 3 } };
	relocOutside.m_unRelocationVaOverride = 0x20000;
	Add( "relocs_outside_sections", relocOutside );

	PeOptions_t noBaseDifference;
	noBaseDifference.m_unImageBase = 0x10000000;
	noBaseDifference.m_Relocs = { { 0x1100, 3 } };
	Add( "at_normal_base", noBaseDifference );

	PeOptions_t pe64;
	pe64.m_bPe64 = true;
	pe64.m_unImageBase = 0x40000000;
	pe64.m_Relocs = { { 0x1100, 10 } };
	pe64.m_cubOverlay = 0x123;
	Add( "pe64_overlay", pe64 );
	Add( "memory_pe64", pe64, true );

	PeOptions_t textBss;
	textBss.m_pszTextName = ".textbss";
	textBss.m_Relocs = { { 0x1100, 3 } };
	Add( "text_prefix_name", textBss );

	PeOptions_t otherName;
	otherName.m_pszTextName = "CODE";
	otherName.m_Relocs = { { 0x1100, 3 } };
	Add( "other_exec_name", otherName );

	PeOptions_t stub;
	stub.m_bValveStub = true;
	stub.m_Relocs = { { 0x1100, 3 } };
	Add( "valve_stub", stub );

	PeOptions_t directories;
	directories.m_Relocs = { { 0x1100, 3 }, { 0x1FFE, 3 } };
	directories.m_Iat = { 0x1FF0, 0x20 };
	directories.m_Export = { 0x2800, 0x10 };
	Add( "iat_and_export_in_text", directories );

	PeOptions_t badMagic;
	badMagic.m_unOptionalMagic = 0x999;
	Add( "bad_optional_magic", badMagic );

	PeOptions_t zeroSections;
	zeroSections.m_cSectionsOverride = 0;
	Add( "zero_sections_overlay", zeroSections );

	std::vector<void *> rgViews;
	for ( Case_t &testCase : rgCases )
	{
		const std::string path = std::string( pszDirectory ) + "\\" + testCase.m_pszName + ".bin";
		HANDLE hWrite =
		    CreateFileA( path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr );
		if ( hWrite == INVALID_HANDLE_VALUE )
		{
			std::printf( "write %s: %lu\n", path.c_str(), GetLastError() );
			return 2;
		}
		DWORD cubWritten = 0;
		WriteFile( hWrite, testCase.m_Pe.m_rgubFile.data(), static_cast<DWORD>( testCase.m_Pe.m_rgubFile.size() ),
		           &cubWritten, nullptr );
		CloseHandle( hWrite );

		HANDLE hFile =
		    CreateFileA( path.c_str(), GENERIC_READ | GENERIC_EXECUTE, testCase.m_bExclusive ? 0 : FILE_SHARE_READ,
		                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
		HANDLE hMapping = CreateFileMappingA( hFile, nullptr, PAGE_EXECUTE_READ, 0, 0, nullptr );
		void *pView = hMapping ? MapViewOfFile( hMapping, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, 0 ) : nullptr;
		if ( !pView )
		{
			std::printf( "map %s: %lu\n", path.c_str(), GetLastError() );
			return 2;
		}
		rgViews.push_back( pView );
		if ( !testCase.m_bExclusive )
			CloseHandle( hFile );
	}

	std::puts( "ready" );
	std::fflush( stdout );
	Sleep( 300000 );
	return 0;
}

} // namespace

int main( int argc, char **argv )
{
	if ( argc == 3 && std::strcmp( argv[1], "--pressure-target" ) == 0 )
		return RunPressureTarget( argv[2] );
	if ( argc == 3 && std::strcmp( argv[1], "--crafted-target" ) == 0 )
		return RunCraftedTarget( argv[2] );

	CheckAllocationWalk();
	CheckLdrCapture();
	CheckCraftedImages();
	CheckEmptyCompression();
	std::printf( "%s: allocation walk, LDR capture, crafted images and empty compression\n",
	             g_cFailures ? "FAIL" : "PASS" );
	return g_cFailures ? 1 : 0;
}
