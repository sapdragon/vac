// @binary: 33211402
#include "../scanner.hpp"
#include "crt/intrinsics.hpp"
#include "crypto/hash/hash488781ed.hpp"
#include "pe/pe.hpp"

namespace vac::workers::image_scan
{

namespace
{

constexpr u64 k_ulNormalizedImageBase = 0x10000000;

// @orig: 80 B9 ? ? ? ? ? 74 ? 8B 81 ? ? ? ? 8B 91
u64 GetImageBase( const ScannerContext_t *pCtx ) noexcept
{
	return pCtx->m_bPe64 ? pCtx->m_OptionalHeader64.ImageBase : pCtx->m_OptionalHeader32.ImageBase;
}

const IMAGE_DATA_DIRECTORY &GetDirectory( const ScannerContext_t *pCtx, u32 iDirectory ) noexcept
{
	return pCtx->m_bPe64 ? pCtx->m_OptionalHeader64.DataDirectory[iDirectory]
	                     : pCtx->m_OptionalHeader32.DataDirectory[iDirectory];
}

// @orig: 51 56 8B F1 57 80 BE
bool LoadBaseRelocTable( ScannerContext_t *pCtx ) noexcept
{
	const IMAGE_DATA_DIRECTORY &directory = GetDirectory( pCtx, IMAGE_DIRECTORY_ENTRY_BASERELOC );
	pCtx->m_cubRelocations = directory.Size;
	if ( !pCtx->m_cubRelocations )
		return true;

	const IMAGE_SECTION_HEADER *pSection =
	    pe::FindSectionByRva( pCtx->m_pSections, pCtx->m_FileHeader.NumberOfSections, directory.VirtualAddress );
	u32 ibFileDelta = 0;
	if ( pSection && pCtx->m_hFile != INVALID_HANDLE_VALUE )
		ibFileDelta = pSection->VirtualAddress - pSection->PointerToRawData;

	if ( !ReaderSeek( pCtx, directory.VirtualAddress - ibFileDelta, false ) )
		return false;

	pCtx->m_pubRelocations = static_cast<u8 *>( AllocBytes( pCtx->m_cubRelocations ) );
	return ReaderReadBytes( pCtx, pCtx->m_pubRelocations, pCtx->m_cubRelocations );
}

// @orig: 8B 81 ? ? ? ? 0B 81 ? ? ? ? 74 ? B0
bool HasRelocationDelta( const ScannerContext_t *pCtx ) noexcept
{
	if ( pCtx->m_ulImageDelta )
		return true;
	if ( pCtx->m_hFile != INVALID_HANDLE_VALUE )
		return false;
	return pCtx->m_ulMappedBase != GetImageBase( pCtx );
}

// @note / sapdragon: only moves on to the next block, so a block crossing the chunk end gets continued by the next call
// @orig: 83 EC ? 8B 44 24
bool NormalizeRelocationsInChunk( ScannerContext_t *pCtx, u8 *pubChunk, u32 unChunkRva, u32 cubChunk,
                                  u32 *pibCursor ) noexcept
{
	const u32 unChunkEnd = unChunkRva + cubChunk;
	u32 ibCursor = *pibCursor;
	while ( ibCursor < pCtx->m_cubRelocations )
	{
		const auto *pBlock = reinterpret_cast<const IMAGE_BASE_RELOCATION *>( pCtx->m_pubRelocations + ibCursor );
		const u32 unPageRva = pBlock->VirtualAddress;
		if ( !unPageRva || !pBlock->SizeOfBlock || unPageRva >= unChunkEnd )
			break;

		const u32 cEntries = ( pBlock->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) >> 1;
		if ( !cEntries )
			break;

		if ( unPageRva + 0x1000 > unChunkRva )
		{
			const auto *punEntries = reinterpret_cast<const u16 *>( pBlock + 1 );
			for ( u32 iEntry = 0; iEntry < cEntries; ++iEntry )
			{
				const u16 unEntry = punEntries[iEntry];
				const u32 unRva = unPageRva + ( unEntry & 0xFFF );
				if ( unRva < unChunkRva )
					continue;
				if ( unRva >= unChunkEnd )
					return true;

				const u32 unType = unEntry >> 12;
				if ( unType == IMAGE_REL_BASED_ABSOLUTE )
					continue;

				u8 *pubTarget = pubChunk + ( unRva - unChunkRva );
				if ( unType == IMAGE_REL_BASED_HIGHLOW )
				{
					const u32 unValue =
					    *reinterpret_cast<u32 *>( pubTarget ) - static_cast<u32>( pCtx->m_ulImageDelta );
					++pCtx->m_cRelocationsApplied;
					*reinterpret_cast<u32 *>( pubTarget ) = pCtx->m_bZeroRelocations ? 0 : unValue;
				}
				else if ( unType == IMAGE_REL_BASED_DIR64 )
				{
					u64 ulValue = 0;
					if ( !pCtx->m_bZeroRelocations )
						ulValue =
						    *reinterpret_cast<u64 *>( pubTarget ) + pCtx->m_ulImageDelta - pCtx->m_ulRelocationBase;
					++pCtx->m_cRelocationsApplied;
					*reinterpret_cast<u64 *>( pubTarget ) = ulValue;
				}
				else
				{
					return false;
				}
			}
		}

		ibCursor = pBlock->SizeOfBlock + *pibCursor;
		*pibCursor = ibCursor;
	}
	return true;
}

// @orig: 80 B9 ? ? ? ? ? BA
void HashExcludingIat( const ScannerContext_t *pCtx, const u8 *pubChunk, u32 unChunkRva, u32 cubChunk,
                       HybridHash_t *pHash ) noexcept
{
	const IMAGE_DATA_DIRECTORY &directory = GetDirectory( pCtx, IMAGE_DIRECTORY_ENTRY_IAT );
	const u32 unChunkEnd = unChunkRva + cubChunk;

	u32 unCutStart = unChunkRva;
	if ( directory.VirtualAddress > unChunkRva )
		unCutStart = directory.VirtualAddress;

	u32 unCutEnd = unChunkEnd;
	if ( directory.VirtualAddress + directory.Size < unChunkEnd )
		unCutEnd = directory.VirtualAddress + directory.Size;

	if ( unCutStart < unCutEnd )
	{
		if ( unCutStart > unChunkRva )
			UpdateHybridHash( pHash, pubChunk, unCutStart - unChunkRva );
		if ( unCutEnd < unChunkEnd )
			UpdateHybridHash( pHash, pubChunk + ( unCutEnd - unChunkRva ), unChunkEnd - unCutEnd );
	}
	else
	{
		UpdateHybridHash( pHash, pubChunk, cubChunk );
	}
}

// @orig: 55 8B EC 83 EC ? 8B 45
void HashExcludingIatAndExports( const ScannerContext_t *pCtx, const u8 *pubChunk, u32 unChunkRva, u32 cubChunk,
                                 HybridHash_t *pHash ) noexcept
{
	const IMAGE_DATA_DIRECTORY &iat = GetDirectory( pCtx, IMAGE_DIRECTORY_ENTRY_IAT );
	const IMAGE_DATA_DIRECTORY &exports = GetDirectory( pCtx, IMAGE_DIRECTORY_ENTRY_EXPORT );

	pe::RangePair_t outer;
	pe::SplitAroundDirectory( iat.VirtualAddress, iat.Size, unChunkRva, unChunkRva + cubChunk, outer );

	pe::RangePair_t rgInner[2];
	pe::SplitAroundDirectory( exports.VirtualAddress, exports.Size, outer.m_rgunStart[0], outer.m_rgunEnd[0],
	                          rgInner[0] );
	pe::SplitAroundDirectory( exports.VirtualAddress, exports.Size, outer.m_rgunStart[1], outer.m_rgunEnd[1],
	                          rgInner[1] );

	for ( const pe::RangePair_t &inner : rgInner )
	{
		for ( u32 iRange = 0; iRange < 2; ++iRange )
		{
			const u32 unStart = inner.m_rgunStart[iRange];
			const u32 unEnd = inner.m_rgunEnd[iRange];
			if ( unEnd > unStart )
				UpdateHybridHash( pHash, pubChunk + ( unStart - unChunkRva ), unEnd - unStart );
		}
	}
}

// @orig: 51 53 8B 5C 24
bool PrepareSectionReaderForHash( ScannerContext_t *pCtx, const IMAGE_SECTION_HEADER *pSection,
                                  const HybridHash_t *pHash ) noexcept
{
	const u32 unRva = pSection->VirtualAddress;
	const u32 cubRaw = pSection->SizeOfRawData;

	if ( !HasRelocationDelta( pCtx ) && pHash &&
	     ( pHash->m_eMode == EHashMode::Md5Rebased || pHash->m_eMode == EHashMode::Md5RebasedAlt ) )
		pCtx->m_ulImageDelta = GetImageBase( pCtx );

	if ( HasRelocationDelta( pCtx ) )
	{
		if ( !pCtx->m_pubRelocations && !LoadBaseRelocTable( pCtx ) )
			return false;
		if ( !pCtx->m_ulImageDelta )
			pCtx->m_ulImageDelta = pCtx->m_ulMappedBase - GetImageBase( pCtx );
	}

	u32 ibOffset = unRva;
	if ( pCtx->m_hFile != INVALID_HANDLE_VALUE )
		ibOffset = pSection->PointerToRawData;
	if ( !ReaderSeek( pCtx, ibOffset, false ) )
		return false;

	pCtx->m_ibRelocationCursor = 0;
	pCtx->m_unSectionRva = unRva;
	pCtx->m_cubSection = cubRaw;
	return true;
}

} // namespace

// @orig: 56 8B F1 C7 46
void ConstructHybridHash( HybridHash_t *pHash ) noexcept
{
	pHash->m_eMode = EHashMode::Md5;
	ResetHybridHash( pHash );
}

// @orig: E8 ? ? ? ? 33 C0 6A
void ResetHybridHash( HybridHash_t *pHash ) noexcept
{
	pHash->m_Md5.Init();
	pHash->m_unLfsr = 0;
	pHash->m_cubTotal = 0;
	memset( pHash->m_rgubDigest, 0, sizeof( pHash->m_rgubDigest ) );
}

// @orig: 51 56 8B F1 57 8B 7C 24
void UpdateHybridHash( HybridHash_t *pHash, const void *pvData, u32 cubData ) noexcept
{
	pHash->m_cubTotal += cubData;
	if ( HasFlag( pHash->m_eMode, EHashMode::Md5 ) )
		pHash->m_Md5.Update( static_cast<const u8 *>( pvData ), cubData );
	else if ( pHash->m_eMode == EHashMode::Lfsr )
		pHash->m_unLfsr =
		    crypto::hash::Hash488781ED_t::Of( static_cast<const u8 *>( pvData ), cubData, pHash->m_unLfsr );
}

// @orig: F6 41 ? ? 74
u32 GetHybridHashResult( const HybridHash_t *pHash, void *pvDst ) noexcept
{
	if ( HasFlag( pHash->m_eMode, EHashMode::Md5 ) )
	{
		memcpy( pvDst, pHash->m_rgubDigest, sizeof( pHash->m_rgubDigest ) );
		return sizeof( pHash->m_rgubDigest );
	}
	if ( pHash->m_eMode == EHashMode::Lfsr )
	{
		memcpy( pvDst, &pHash->m_unLfsr, sizeof( pHash->m_unLfsr ) );
		return sizeof( pHash->m_unLfsr );
	}
	return 0;
}

// @note / sapdragon: a failed normalize returns without freeing the chunk, the original leaks it too
// @orig: 51 53 55 56 57 FF 74 24
bool HashSectionWithFixups( ScannerContext_t *pCtx, const IMAGE_SECTION_HEADER *pSection, HybridHash_t *pHash ) noexcept
{
	if ( !PrepareSectionReaderForHash( pCtx, pSection, pHash ) )
		return false;

	u32 cubChunk = 0;
	u8 *pubChunk = nullptr;
	const u32 iSection = static_cast<u32>( pSection - pCtx->m_pSections );
	if ( iSection < pCtx->m_FileHeader.NumberOfSections )
	{
		const IMAGE_SECTION_HEADER &section = pCtx->m_pSections[iSection];
		u32 ibOffset = section.VirtualAddress;
		const u32 cubRaw = section.SizeOfRawData;
		if ( pCtx->m_hFile != INVALID_HANDLE_VALUE )
			ibOffset = section.PointerToRawData;
		pubChunk = static_cast<u8 *>( AllocBytes( section.SizeOfRawData ) );
		cubChunk = ReaderReadAt( pCtx, ibOffset, pubChunk, cubRaw );
	}

	if ( HasRelocationDelta( pCtx ) &&
	     !NormalizeRelocationsInChunk( pCtx, pubChunk, pCtx->m_unSectionRva, cubChunk, &pCtx->m_ibRelocationCursor ) )
		return false;

	if ( pCtx->m_bLoadedImagePass )
		HashExcludingIat( pCtx, pubChunk, pCtx->m_unSectionRva, cubChunk, pHash );
	else
		HashExcludingIatAndExports( pCtx, pubChunk, pCtx->m_unSectionRva, cubChunk, pHash );

	if ( pubChunk )
		FreeBytes( pubChunk );
	return true;
}

// @orig: 81 EC ? ? ? ? 53 55 56 57 8B BC 24
bool HashAllSections( ScannerContext_t *pCtx, HybridHash_t *pHash ) noexcept
{
	if ( !pHash )
		return false;

	if ( !pCtx->m_bLoadedImagePass )
	{
		const u64 ulBase = pCtx->m_hFile == INVALID_HANDLE_VALUE ? pCtx->m_ulMappedBase : GetImageBase( pCtx );
		if ( pCtx->m_bPe64 )
		{
			pCtx->m_ulRelocationBase = ulBase;
			pCtx->m_ulImageDelta = k_ulNormalizedImageBase;
		}
		else
		{
			pCtx->m_ulImageDelta = ulBase - k_ulNormalizedImageBase;
		}
	}

	UpdateHybridHash( pHash, &pCtx->m_DosHeader, sizeof( pCtx->m_DosHeader ) );
	UpdateHybridHash( pHash, pCtx->m_bLoadedImagePass ? &pCtx->m_FileHeader : &pCtx->m_RawFileHeader,
	                  sizeof( IMAGE_FILE_HEADER ) );

	IMAGE_OPTIONAL_HEADER64 optionalHeader64;
	IMAGE_OPTIONAL_HEADER32 optionalHeader32;
	memcpy( &optionalHeader64, &pCtx->m_OptionalHeader64, sizeof( optionalHeader64 ) );
	memcpy( &optionalHeader32, &pCtx->m_OptionalHeader32, sizeof( optionalHeader32 ) );
	if ( !pCtx->m_bLoadedImagePass )
	{
		optionalHeader64.ImageBase = 0;
		optionalHeader32.ImageBase = 0;
	}

	if ( pCtx->m_bPe64 )
		UpdateHybridHash( pHash, &optionalHeader64, sizeof( optionalHeader64 ) );
	else
		UpdateHybridHash( pHash, &optionalHeader32, sizeof( optionalHeader32 ) );

	const u32 cSections = pCtx->m_FileHeader.NumberOfSections;
	if ( !cSections )
		return false;

	const IMAGE_SECTION_HEADER *pSelected = nullptr;
	bool bFoundText = false;
	u32 cubLargest = 0;
	for ( u32 iSection = 0; iSection < cSections; ++iSection )
	{
		const IMAGE_SECTION_HEADER *pSection = &pCtx->m_pSections[iSection];

		// @note / sapdragon: the normal pass leaves the synthetic .extra out by using the raw count
		if ( iSection < pCtx->m_RawFileHeader.NumberOfSections || pCtx->m_bLoadedImagePass )
		{
			UpdateHybridHash( pHash, pSection->Name, sizeof( pSection->Name ) );
			UpdateHybridHash( pHash, &pSection->VirtualAddress, sizeof( pSection->VirtualAddress ) );
			UpdateHybridHash( pHash, &pSection->SizeOfRawData, sizeof( pSection->SizeOfRawData ) );
		}

		const bool bExecutable = ( pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE ) != 0;
		if ( !CompareNameBounded( reinterpret_cast<const char *>( pSection->Name ), ".text", 5 ) && bExecutable )
		{
			bFoundText = true;
			pSelected = pSection;
		}
		else if ( !bFoundText && bExecutable && pSection->SizeOfRawData > cubLargest )
		{
			cubLargest = pSection->SizeOfRawData;
			pSelected = pSection;
		}
	}

	if ( !pSelected || !HashSectionWithFixups( pCtx, pSelected, pHash ) )
		return false;

	if ( HasFlag( pHash->m_eMode, EHashMode::Md5 ) )
		pHash->m_Md5.Final( pHash->m_rgubDigest );
	return true;
}

} // namespace vac::workers::image_scan
