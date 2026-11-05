// @binary: 33211402
#include "../scanner.hpp"
#include "crt/intrinsics.hpp"
#include "pe/pe.hpp"

namespace vac::workers::image_scan
{

namespace
{

constexpr u32 k_unRsdsSignature = 0x53445352;

struct CodeViewHeader_t
{
	u32 m_unSignature;
	u8 m_rgubGuidAge[20];
};
VAC_LAYOUT_SIZE( CodeViewHeader_t, 24 );

} // namespace

// @orig: 83 EC ? 53 55 56 57 8B F1
EScanStatus ExtractPdbInfo( ScannerContext_t *pCtx ) noexcept
{
	memset( &pCtx->m_DebugDirectory, 0, sizeof( pCtx->m_DebugDirectory ) );
	memset( pCtx->m_rgubPdbGuid, 0, sizeof( pCtx->m_rgubPdbGuid ) );
	memset( pCtx->m_szPdbPath, 0, sizeof( pCtx->m_szPdbPath ) );

	const IMAGE_DATA_DIRECTORY &directory = pCtx->m_bPe64
	                                            ? pCtx->m_OptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]
	                                            : pCtx->m_OptionalHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	if ( !directory.Size )
		return EScanStatus::NoDebugDirectory;

	const IMAGE_SECTION_HEADER *pSection =
	    pe::FindSectionByRva( pCtx->m_pSections, pCtx->m_FileHeader.NumberOfSections, directory.VirtualAddress );
	if ( !pSection )
		return EScanStatus::NoDebugSection;

	u32 ibFileDelta = 0;
	if ( pCtx->m_hFile != INVALID_HANDLE_VALUE )
		ibFileDelta = pSection->VirtualAddress - pSection->PointerToRawData;

	if ( !ReaderSeek( pCtx, directory.VirtualAddress - ibFileDelta, false ) )
		return EScanStatus::SeekFailed;

	SetReaderClamp( pCtx, pSection->VirtualAddress, pSection->VirtualAddress + pSection->Misc.VirtualSize );

	// @note / sapdragon: a short read ends the search and the function still returns zero
	u32 cubLeft = directory.Size;
	bool bFound = false;
	while ( !bFound && cubLeft >= sizeof( IMAGE_DEBUG_DIRECTORY ) )
	{
		memset( &pCtx->m_DebugDirectory, 0, sizeof( pCtx->m_DebugDirectory ) );
		if ( !ReaderReadBytes( pCtx, &pCtx->m_DebugDirectory, sizeof( pCtx->m_DebugDirectory ) ) )
			break;
		cubLeft -= sizeof( IMAGE_DEBUG_DIRECTORY );
		bFound = pCtx->m_DebugDirectory.Type == IMAGE_DEBUG_TYPE_CODEVIEW;
	}

	if ( bFound && ReaderSeek( pCtx, pCtx->m_DebugDirectory.AddressOfRawData - ibFileDelta, false ) )
	{
		const u32 cubCodeView = pCtx->m_DebugDirectory.SizeOfData;
		u32 unSignature;
		if ( cubCodeView >= sizeof( unSignature ) && ReaderReadBytes( pCtx, &unSignature, sizeof( unSignature ) ) &&
		     unSignature == k_unRsdsSignature && cubCodeView >= sizeof( CodeViewHeader_t ) )
		{
			u8 rgubGuidAge[sizeof( CodeViewHeader_t::m_rgubGuidAge )];
			if ( ReaderReadBytes( pCtx, rgubGuidAge, sizeof( rgubGuidAge ) ) )
			{
				u32 cubPath = cubCodeView - sizeof( CodeViewHeader_t );
				memcpy( pCtx->m_rgubPdbGuid, rgubGuidAge, sizeof( pCtx->m_rgubPdbGuid ) );
				if ( cubPath > sizeof( pCtx->m_szPdbPath ) )
					cubPath = sizeof( pCtx->m_szPdbPath );
				ReaderReadBytes( pCtx, pCtx->m_szPdbPath, cubPath );
				pCtx->m_szPdbPath[sizeof( pCtx->m_szPdbPath ) - 1] = 0;
			}
		}
	}

	SetReaderClamp( pCtx, 0, 0 );
	return EScanStatus::Ok;
}

} // namespace vac::workers::image_scan
