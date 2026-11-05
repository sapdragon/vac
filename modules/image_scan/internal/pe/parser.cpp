// @binary: 33211402
#include "../scanner.hpp"
#include "bootstrap/bootstrap.hpp"
#include "crt/intrinsics.hpp"
#include "file/file.hpp"
#include "pe/pe.hpp"

namespace vac::workers::image_scan
{

namespace
{

constexpr char k_szExtraSection[] = ".extra";

} // namespace

// @orig: 53 33 DB 56 8B F1
void InitScannerContext( ScannerContext_t *pCtx ) noexcept
{
	pCtx->m_hFile = INVALID_HANDLE_VALUE;
	pCtx->m_cubWindow = 0;
	pCtx->m_ulWindowBase = 0;
	pCtx->m_ibWindow = 0;
	pCtx->m_ulClampStart = 0;
	pCtx->m_ulClampEnd = 0;
	pCtx->m_hProcess = nullptr;
	pCtx->m_ulRelocationBase = 0;
	pCtx->m_cubMapped = 0;
	pCtx->m_pSections = nullptr;
	pCtx->m_ppSectionData = nullptr;
	pCtx->m_cResourceEntries = 0;
	pCtx->m_ppResourceData = nullptr;
	pCtx->m_pResourceTable = nullptr;
	pCtx->m_pubRelocations = nullptr;
	pCtx->m_cSectionBuffers = 0;
	pCtx->m_cubRelocations = 0;
	pCtx->m_bUnused4 = 0;
	pCtx->m_unUnused3 = 0;
	pCtx->m_ulImageDelta = 0;
	pCtx->m_bZeroRelocations = 0;
	pCtx->m_bPe64 = 0;
	memset( pCtx->m_rgpSectionBuffers, 0, sizeof( pCtx->m_rgpSectionBuffers ) );
	pCtx->m_cRelocationsApplied = 0;
	pCtx->m_szPdbPath[0] = 0;
	pCtx->m_bLoadedImagePass = 0;
}

// @orig: 53 0F B7 99 ? ? ? ? 56
const IMAGE_SECTION_HEADER *FindExtraSection( const ScannerContext_t *pCtx ) noexcept
{
	const u32 cSections = pCtx->m_FileHeader.NumberOfSections;
	for ( u32 iSection = 0; iSection < cSections; ++iSection )
	{
		const IMAGE_SECTION_HEADER *pSection = &pCtx->m_pSections[iSection];
		if ( !CompareNameBounded( reinterpret_cast<const char *>( pSection->Name ), k_szExtraSection,
		                          sizeof( pSection->Name ) ) )
			return pSection;
	}
	return nullptr;
}

// @orig: 83 EC ? BA
EScanStatus ParsePeHeader( ScannerContext_t *pCtx ) noexcept
{
	SetReaderClamp( pCtx, 0, 0x1000 );

	if ( !ReaderReadBytes( pCtx, &pCtx->m_DosHeader, sizeof( pCtx->m_DosHeader ) ) )
		return EScanStatus::ReadFailed;
	if ( pCtx->m_DosHeader.e_magic != IMAGE_DOS_SIGNATURE )
		return EScanStatus::BadImage;

	if ( !ReaderReadBytes( pCtx, pCtx->m_rgubDosStub, sizeof( pCtx->m_rgubDosStub ) ) )
		return EScanStatus::ReadFailed;

	if ( !ReaderSeek( pCtx, static_cast<u32>( pCtx->m_DosHeader.e_lfanew ), false ) )
		return EScanStatus::SeekFailed;

	u32 unSignature;
	if ( !ReaderReadBytes( pCtx, &unSignature, sizeof( unSignature ) ) )
		return EScanStatus::ReadFailed;
	if ( unSignature != IMAGE_NT_SIGNATURE )
		return EScanStatus::BadImage;

	if ( !ReaderReadBytes( pCtx, &pCtx->m_RawFileHeader, sizeof( pCtx->m_RawFileHeader ) ) )
		return EScanStatus::ReadFailed;
	memcpy( &pCtx->m_FileHeader, &pCtx->m_RawFileHeader, sizeof( pCtx->m_FileHeader ) );

	const WORD unMachine = pCtx->m_FileHeader.Machine;
	if ( ( unMachine != IMAGE_FILE_MACHINE_I386 && unMachine != IMAGE_FILE_MACHINE_AMD64 ) ||
	     pCtx->m_FileHeader.NumberOfSections > pe::k_cMaxSections )
		return EScanStatus::BadImage;

	const WORD cubOptionalHeader = pCtx->m_FileHeader.SizeOfOptionalHeader;
	if ( cubOptionalHeader == sizeof( IMAGE_OPTIONAL_HEADER64 ) )
	{
		if ( !ReaderReadBytes( pCtx, &pCtx->m_OptionalHeader64, sizeof( pCtx->m_OptionalHeader64 ) ) )
			return EScanStatus::ReadFailed;
		if ( pCtx->m_OptionalHeader64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC )
			return EScanStatus::BadOptionalHeader;
		pCtx->m_bPe64 = 1;
	}
	else if ( cubOptionalHeader == sizeof( IMAGE_OPTIONAL_HEADER32 ) )
	{
		if ( !ReaderReadBytes( pCtx, &pCtx->m_OptionalHeader32, sizeof( pCtx->m_OptionalHeader32 ) ) )
			return EScanStatus::ReadFailed;
		if ( pCtx->m_OptionalHeader32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC )
			return EScanStatus::BadOptionalHeader;
	}
	else
	{
		return EScanStatus::BadOptionalHeader;
	}

	const u32 cSections = pCtx->m_FileHeader.NumberOfSections;
	pCtx->m_pSections = static_cast<IMAGE_SECTION_HEADER *>( AllocBytes( sizeof( IMAGE_SECTION_HEADER ) * cSections ) );
	for ( u32 iSection = 0; iSection < cSections; ++iSection )
	{
		if ( !ReaderReadBytes( pCtx, &pCtx->m_pSections[iSection], sizeof( IMAGE_SECTION_HEADER ) ) )
			return EScanStatus::ReadFailed;
	}

	pCtx->m_ulRelocationBase = pCtx->m_bPe64 ? pCtx->m_OptionalHeader64.ImageBase : pCtx->m_OptionalHeader32.ImageBase;
	SetReaderClamp( pCtx, 0, 0 );
	return EScanStatus::Ok;
}

// @orig: 53 56 57 8B D9 E8
EScanStatus SetMemoryMapping( ScannerContext_t *pCtx, u64 ulBase, u32 cubMapped, HANDLE hProcess ) noexcept
{
	CleanupScannerContext( pCtx );
	pCtx->m_ulRelocationBase = ulBase;
	pCtx->m_cubMapped = cubMapped;
	CloseReader( pCtx );
	pCtx->m_ulMappedBase = ulBase;
	pCtx->m_hProcess = hProcess;
	return EScanStatus::Ok;
}

// @orig: 55 8B EC 51 51 56 57
EScanStatus OpenFileById( ScannerContext_t *pCtx, u32 unVolumeSerial, u64 ulFileId, u32 *punLastError ) noexcept
{
	CleanupScannerContext( pCtx );

	HANDLE hFile = INVALID_HANDLE_VALUE;
	const EScanStatus eStatus = static_cast<EScanStatus>(
	    file::OpenByVolumeAndId( g_pImports, unVolumeSerial, ulFileId, FILE_GENERIC_READ, &hFile, punLastError ) );
	if ( eStatus != EScanStatus::Ok )
		return eStatus;

	if ( AttachFileHandle( pCtx, hFile ) )
		return EScanStatus::Ok;

	*punLastError = g_pImports->GetLastError();
	return EScanStatus::OpenFailed;
}

// @note / sapdragon: adds a fake .extra section for whatever follows the last one. m_RawFileHeader keeps the real count
// @orig: 51 53 55 56 8B F1
EScanStatus DeepPeScan( ScannerContext_t *pCtx ) noexcept
{
	if ( pCtx->m_hFile == INVALID_HANDLE_VALUE )
		return EScanStatus::NoFile;

	const EScanStatus eStatus = ParsePeHeader( pCtx );
	if ( eStatus != EScanStatus::Ok )
	{
		CleanupScannerContext( pCtx );
		return eStatus;
	}

	u32 ibSectionsEnd = 0;
	for ( u32 iSection = 0; iSection < pCtx->m_FileHeader.NumberOfSections; ++iSection )
	{
		const u32 ibEnd = pCtx->m_pSections[iSection].PointerToRawData + pCtx->m_pSections[iSection].SizeOfRawData;
		if ( ibEnd > ibSectionsEnd )
			ibSectionsEnd = ibEnd;
	}

	const u32 cubFile = file::GetFileSizeOrZero( g_pImports, pCtx->m_hFile );
	const u32 cubAlignment =
	    pCtx->m_bPe64 ? pCtx->m_OptionalHeader64.SectionAlignment : pCtx->m_OptionalHeader32.SectionAlignment;
	if ( ibSectionsEnd < cubFile )
	{
		const u32 cubOverlay = cubFile - ibSectionsEnd;
		++pCtx->m_FileHeader.NumberOfSections;
		pCtx->m_pSections = static_cast<IMAGE_SECTION_HEADER *>(
		    ReallocBytes( pCtx->m_pSections, sizeof( IMAGE_SECTION_HEADER ) * pCtx->m_FileHeader.NumberOfSections ) );

		IMAGE_SECTION_HEADER *pExtra = &pCtx->m_pSections[pCtx->m_FileHeader.NumberOfSections - 1];
		const IMAGE_SECTION_HEADER *pLast = pExtra - 1;
		u32 cubLast = pLast->Misc.VirtualSize;
		if ( cubLast < pLast->SizeOfRawData )
			cubLast =
			    cubAlignment + pLast->SizeOfRawData - 1 - ( cubAlignment + pLast->SizeOfRawData - 1 ) % cubAlignment;
		const u32 unVirtualEnd = cubAlignment + cubLast + pLast->VirtualAddress - 1;

		memset( pExtra, 0, sizeof( *pExtra ) );
		pExtra->PointerToRawData = ibSectionsEnd;
		pExtra->Characteristics = IMAGE_SCN_MEM_DISCARDABLE;
		pExtra->SizeOfRawData = cubOverlay;
		pExtra->VirtualAddress = unVirtualEnd - unVirtualEnd % cubAlignment;
		pExtra->Misc.VirtualSize = cubAlignment + cubOverlay - 1 - ( cubAlignment + cubOverlay - 1 ) % cubAlignment;
		memcpy( pExtra->Name, k_szExtraSection, sizeof( k_szExtraSection ) );
	}
	return EScanStatus::Ok;
}

// @orig: 53 56 57 8B F1
void CleanupScannerContext( ScannerContext_t *pCtx ) noexcept
{
	CloseReader( pCtx );

	if ( pCtx->m_pSections )
		FreeBytes( pCtx->m_pSections );

	if ( pCtx->m_cResourceEntries > 0 )
	{
		if ( pCtx->m_ppResourceData )
		{
			for ( i32 iEntry = 0; iEntry < pCtx->m_cResourceEntries; ++iEntry )
			{
				if ( pCtx->m_ppResourceData[iEntry] )
					FreeBytes( pCtx->m_ppResourceData[iEntry] );
			}
			FreeBytes( pCtx->m_ppResourceData );
		}
		if ( pCtx->m_pResourceTable )
			FreeBytes( pCtx->m_pResourceTable );
	}

	for ( i32 iBuffer = 0; iBuffer < pCtx->m_cSectionBuffers; ++iBuffer )
		FreeBytes( pCtx->m_rgpSectionBuffers[iBuffer] );

	if ( pCtx->m_pubRelocations )
		FreeBytes( pCtx->m_pubRelocations );

	if ( pCtx->m_ppSectionData )
	{
		for ( u32 iSection = 0; iSection < pCtx->m_FileHeader.NumberOfSections; ++iSection )
		{
			if ( pCtx->m_ppSectionData[iSection] )
				FreeBytes( pCtx->m_ppSectionData[iSection] );
		}
		FreeBytes( pCtx->m_ppSectionData );
	}

	pCtx->m_ulRelocationBase = 0;
	pCtx->m_cubMapped = 0;
	pCtx->m_pSections = nullptr;
	pCtx->m_ppSectionData = nullptr;
	pCtx->m_cResourceEntries = 0;
	pCtx->m_ppResourceData = nullptr;
	pCtx->m_pResourceTable = nullptr;
	pCtx->m_cSectionBuffers = 0;
	pCtx->m_pubRelocations = nullptr;
	pCtx->m_cubRelocations = 0;
	pCtx->m_bUnused4 = 0;
	pCtx->m_unUnused3 = 0;
	pCtx->m_ulImageDelta = 0;
	pCtx->m_bZeroRelocations = 0;
	pCtx->m_bPe64 = 0;
	memset( pCtx->m_rgpSectionBuffers, 0, sizeof( pCtx->m_rgpSectionBuffers ) );
	pCtx->m_cRelocationsApplied = 0;
}

} // namespace vac::workers::image_scan
