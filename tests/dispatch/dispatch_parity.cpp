// Compares the whole runfunc of an original module and a rebuild, including ICE and RSA.
//
//     dispatch_parity.exe <original.dll> <rebuild.dll> <input_packet.bin>
//
// Both images are mapped by hand, the way VAC's own loader does it: read-write-execute and without
// running the entry point at load. Each case gets fresh images, because runfunc leaves state behind.
// rdtsc is patched to a constant so the session key and padding become deterministic.

#include <windows.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace
{

using PfnRunFunc_t = int( __stdcall * )( int, void *, unsigned, void *, unsigned * );

constexpr unsigned k_cubResponse = 0x1088;

std::vector<unsigned char> ReadFileBytes( const char *pszPath )
{
	std::ifstream file( pszPath, std::ios::binary );
	return { std::istreambuf_iterator<char>( file ), {} };
}

struct MappedImage_t
{
	unsigned char *m_pubBase = nullptr;
	PfnRunFunc_t m_pfnRunFunc = nullptr;
	int m_cPatchedRdtsc = 0;
};

MappedImage_t MapImage( const std::vector<unsigned char> &file )
{
	const auto *pDos = reinterpret_cast<const IMAGE_DOS_HEADER *>( file.data() );
	const auto *pNt = reinterpret_cast<const IMAGE_NT_HEADERS32 *>( file.data() + pDos->e_lfanew );

	MappedImage_t image;
	image.m_pubBase = static_cast<unsigned char *>(
		VirtualAlloc( nullptr, pNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) );
	std::memcpy( image.m_pubBase, file.data(), pNt->OptionalHeader.SizeOfHeaders );

	const IMAGE_SECTION_HEADER *pSections = IMAGE_FIRST_SECTION( pNt );
	for ( unsigned iSection = 0; iSection < pNt->FileHeader.NumberOfSections; ++iSection )
	{
		const IMAGE_SECTION_HEADER &section = pSections[iSection];
		std::memcpy( image.m_pubBase + section.VirtualAddress, file.data() + section.PointerToRawData, section.SizeOfRawData );
	}

	const auto &relocDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	const unsigned unDelta = static_cast<unsigned>( reinterpret_cast<UINT_PTR>( image.m_pubBase ) ) - pNt->OptionalHeader.ImageBase;
	for ( unsigned ib = 0; ib < relocDir.Size; )
	{
		const auto *pBlock = reinterpret_cast<const IMAGE_BASE_RELOCATION *>( image.m_pubBase + relocDir.VirtualAddress + ib );
		const auto *punEntries = reinterpret_cast<const unsigned short *>( pBlock + 1 );
		const unsigned cEntries = ( pBlock->SizeOfBlock - sizeof( *pBlock ) ) / 2;
		for ( unsigned iEntry = 0; iEntry < cEntries; ++iEntry )
		{
			if ( punEntries[iEntry] >> 12 == IMAGE_REL_BASED_HIGHLOW )
				*reinterpret_cast<unsigned *>( image.m_pubBase + pBlock->VirtualAddress + ( punEntries[iEntry] & 0xFFF ) ) += unDelta;
		}
		ib += pBlock->SizeOfBlock;
	}

	const auto &importDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	auto *pImport = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>( image.m_pubBase + importDir.VirtualAddress );
	for ( ; pImport->Name; ++pImport )
	{
		const HMODULE hLibrary = LoadLibraryA( reinterpret_cast<const char *>( image.m_pubBase + pImport->Name ) );
		auto *pThunk = reinterpret_cast<IMAGE_THUNK_DATA32 *>( image.m_pubBase + pImport->FirstThunk );
		auto *pName = reinterpret_cast<IMAGE_THUNK_DATA32 *>( image.m_pubBase + ( pImport->OriginalFirstThunk ? pImport->OriginalFirstThunk : pImport->FirstThunk ) );
		for ( ; pName->u1.AddressOfData; ++pThunk, ++pName )
		{
			const auto *pByName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME *>( image.m_pubBase + pName->u1.AddressOfData );
			pThunk->u1.Function = static_cast<DWORD>( reinterpret_cast<UINT_PTR>( GetProcAddress( hLibrary, pByName->Name ) ) );
		}
	}

	const auto &exportDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	const auto *pExports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>( image.m_pubBase + exportDir.VirtualAddress );
	const auto *punFunctions = reinterpret_cast<const DWORD *>( image.m_pubBase + pExports->AddressOfFunctions );
	image.m_pfnRunFunc = reinterpret_cast<PfnRunFunc_t>( image.m_pubBase + punFunctions[0] );

	for ( unsigned iSection = 0; iSection < pNt->FileHeader.NumberOfSections; ++iSection )
	{
		const IMAGE_SECTION_HEADER &section = pSections[iSection];
		if ( !( section.Characteristics & IMAGE_SCN_MEM_EXECUTE ) )
			continue;
		unsigned char *pubCode = image.m_pubBase + section.VirtualAddress;
		for ( unsigned ib = 0; ib + 1 < section.Misc.VirtualSize; ++ib )
		{
			if ( pubCode[ib] == 0x0F && pubCode[ib + 1] == 0x31 )
			{
				pubCode[ib] = 0x31; // xor eax, eax
				pubCode[ib + 1] = 0xC0;
				++image.m_cPatchedRdtsc;
			}
		}
	}
	return image;
}

struct Result_t
{
	int m_nResult;
	unsigned m_cubOutput;
	std::array<unsigned char, k_cubResponse> m_rgubOutput;
};

Result_t RunCase( const std::vector<unsigned char> &file, int nMode, std::vector<unsigned char> packet, unsigned cubInput, unsigned cubCapacity )
{
	MappedImage_t image = MapImage( file );
	Result_t result{};
	result.m_cubOutput = cubCapacity;
	result.m_nResult = image.m_pfnRunFunc( nMode, packet.data(), cubInput, result.m_rgubOutput.data(), &result.m_cubOutput );
	VirtualFree( image.m_pubBase, 0, MEM_RELEASE );
	return result;
}

} // namespace

int main( int argc, char **argv )
{
	if ( argc != 4 )
		return 2;

	const auto original = ReadFileBytes( argv[1] );
	const auto rebuild = ReadFileBytes( argv[2] );
	const auto packet = ReadFileBytes( argv[3] );
	if ( original.empty() || rebuild.empty() || packet.size() < 0xB0 )
		return 3;

	auto badCrc = packet;
	badCrc[8] ^= 0xFF;
	auto wrongId = packet;
	wrongId[0] ^= 0xFF;

	struct Case_t
	{
		const char *m_pszName;
		int m_nMode;
		const std::vector<unsigned char> *m_pPacket;
		unsigned m_cubInput;
		unsigned m_cubCapacity;
	};
	const Case_t rgCases[] = {
		{ "full_response", 4, &packet, static_cast<unsigned>( packet.size() ), k_cubResponse },
		{ "other_session_id", 4, &packet, static_cast<unsigned>( packet.size() ), k_cubResponse },
		{ "bad_crc", 4, &badCrc, static_cast<unsigned>( packet.size() ), k_cubResponse },
		{ "unknown_module", 4, &wrongId, static_cast<unsigned>( packet.size() ), k_cubResponse },
		{ "short_input", 4, &packet, 0xAF, k_cubResponse },
		{ "tiny_capacity", 4, &packet, static_cast<unsigned>( packet.size() ), 0xF },
		{ "small_capacity", 4, &packet, static_cast<unsigned>( packet.size() ), 0xFFF },
		{ "other_mode", 3, &packet, static_cast<unsigned>( packet.size() ), k_cubResponse },
	};

	const MappedImage_t probe = MapImage( rebuild );
	const MappedImage_t probeOriginal = MapImage( original );
	std::printf( "patched rdtsc: original=%d rebuild=%d\n", probeOriginal.m_cPatchedRdtsc, probe.m_cPatchedRdtsc );

	int cFailures = 0;
	for ( const Case_t &testCase : rgCases )
	{
		auto input = *testCase.m_pPacket;
		if ( !std::strcmp( testCase.m_pszName, "other_session_id" ) )
			input[0x0C] ^= 0x5A;

		const Result_t expected = RunCase( original, testCase.m_nMode, input, testCase.m_cubInput, testCase.m_cubCapacity );
		const Result_t actual = RunCase( rebuild, testCase.m_nMode, input, testCase.m_cubInput, testCase.m_cubCapacity );

		unsigned cDifferent = 0;
		unsigned ibFirst = 0;
		for ( unsigned ib = 0; ib < k_cubResponse; ++ib )
		{
			if ( expected.m_rgubOutput[ib] != actual.m_rgubOutput[ib] )
			{
				if ( !cDifferent )
					ibFirst = ib;
				++cDifferent;
			}
		}
		const bool bOk = !cDifferent && expected.m_nResult == actual.m_nResult && expected.m_cubOutput == actual.m_cubOutput;
		cFailures += !bOk;
		if ( const char *pszDump = std::getenv( "VAC_DISPATCH_DUMP" ) )
		{
			const std::string base = std::string( pszDump ) + "/" + testCase.m_pszName;
			std::ofstream( base + ".original.bin", std::ios::binary ).write( reinterpret_cast<const char *>( expected.m_rgubOutput.data() ), k_cubResponse );
			std::ofstream( base + ".rebuild.bin", std::ios::binary ).write( reinterpret_cast<const char *>( actual.m_rgubOutput.data() ), k_cubResponse );
		}
		std::printf( "%-4s %-18s result=%d/%d size=0x%x/0x%x diff=%u first=0x%x\n", bOk ? "ok" : "FAIL", testCase.m_pszName,
			expected.m_nResult, actual.m_nResult, expected.m_cubOutput, actual.m_cubOutput, cDifferent, ibFirst );
	}
	std::printf( "failures=%d\n", cFailures );
	return cFailures ? 1 : 0;
}
