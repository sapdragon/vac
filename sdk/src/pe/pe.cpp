// @binary: 42878040
#include "pe/pe.hpp"
#include "crt/intrinsics.hpp"
#include "util/strings.hpp"

namespace vac::pe
{

namespace
{

constexpr char k_szTextSection[] = ".text";
constexpr char k_szOverlaySection[] = ".extra";

} // namespace

const IMAGE_DATA_DIRECTORY *GetDataDirectory( const void *pOptionalHeader, bool bPe64, u32 iDirectory ) noexcept
{
	if ( bPe64 )
		return &static_cast<const IMAGE_OPTIONAL_HEADER64 *>( pOptionalHeader )->DataDirectory[iDirectory];
	return &static_cast<const IMAGE_OPTIONAL_HEADER32 *>( pOptionalHeader )->DataDirectory[iDirectory];
}

// @orig: 56 0F B7 B1
const IMAGE_SECTION_HEADER *FindSectionByRva( const IMAGE_SECTION_HEADER *pSections, u32 cSections, u32 unRva ) noexcept
{
	for ( u32 iSection = 0; iSection < cSections; ++iSection )
	{
		const IMAGE_SECTION_HEADER &section = pSections[iSection];
		u32 cubExtent = section.SizeOfRawData;
		if ( cubExtent )
		{
			if ( section.Misc.VirtualSize )
				cubExtent = section.Misc.VirtualSize;
			if ( unRva >= section.VirtualAddress && unRva < section.VirtualAddress + cubExtent )
				return &section;
		}
	}
	return nullptr;
}

// @orig: 53 0F B7 99 ? ? ? ? 83 CA
u32 RvaToFileOffset( const IMAGE_SECTION_HEADER *pSections, u32 cSections, u32 unRva ) noexcept
{
	for ( u32 iSection = 0; iSection < cSections; ++iSection )
	{
		const IMAGE_SECTION_HEADER &section = pSections[iSection];
		if ( unRva >= section.VirtualAddress && unRva < section.VirtualAddress + section.SizeOfRawData )
			return unRva + section.PointerToRawData - section.VirtualAddress;
	}
	return k_unInvalidOffset;
}

bool RvaToFileOffsetLargestSpan( const IMAGE_SECTION_HEADER *pSections, u32 cSections, u32 unRva,
                                 u32 *pibFileOffset ) noexcept
{
	for ( u32 iSection = 0; iSection < cSections; ++iSection )
	{
		const IMAGE_SECTION_HEADER &section = pSections[iSection];
		u32 cubSpan = section.Misc.VirtualSize;
		if ( cubSpan < section.SizeOfRawData )
			cubSpan = section.SizeOfRawData;
		if ( unRva >= section.VirtualAddress && unRva < section.VirtualAddress + cubSpan )
		{
			*pibFileOffset = section.PointerToRawData + unRva - section.VirtualAddress;
			return true;
		}
	}
	return false;
}

// @orig: 51 80 B9
void SplitAroundDirectory( u32 unDirectoryVa, u32 cubDirectory, u32 unStart, u32 unEnd, RangePair_t &ranges ) noexcept
{
	ranges.m_rgunStart[0] = ranges.m_rgunEnd[0] = ranges.m_rgunStart[1] = ranges.m_rgunEnd[1] = 0;

	u32 unCutStart = unDirectoryVa;
	if ( unCutStart < unStart )
		unCutStart = unStart;

	// @note / sapdragon: the sum can wrap on a corrupt directory. no clamp, valve's check does not have one either
	u32 unCutEnd = unEnd;
	if ( unDirectoryVa + cubDirectory + 4 < unEnd )
		unCutEnd = unDirectoryVa + cubDirectory + 4;

	if ( unCutStart >= unCutEnd )
	{
		ranges.m_rgunStart[0] = unStart;
		ranges.m_rgunEnd[0] = unEnd;
		return;
	}

	if ( unCutEnd < unEnd )
	{
		ranges.m_rgunStart[1] = unCutEnd;
		ranges.m_rgunEnd[1] = unEnd;
	}
	if ( unCutStart <= unStart )
	{
		ranges.m_rgunStart[0] = ranges.m_rgunStart[1];
		ranges.m_rgunEnd[0] = ranges.m_rgunEnd[1];
		ranges.m_rgunStart[1] = 0;
		ranges.m_rgunEnd[1] = 0;
	}
	else
	{
		ranges.m_rgunStart[0] = unStart;
		ranges.m_rgunEnd[0] = unCutStart;
	}
}

// @note / sapdragon: rebuilt modules' behaviour, not valve's loop. the original fails on unknown entry types and
// patches a value that crosses the chunk end, this skips both
// @orig: 51 51 8B 44 24
bool ApplyRelocationsForHash( const u8 *pubFile, u32 cubFile, const IMAGE_SECTION_HEADER *pSections, u32 cSections,
                              const IMAGE_DATA_DIRECTORY &relocations, u32 unImageBase, u32 unChunkRva, u8 *pubChunk,
                              u32 cubChunk ) noexcept
{
	if ( !relocations.VirtualAddress || relocations.Size < sizeof( IMAGE_BASE_RELOCATION ) || !unImageBase )
		return true;

	u32 ibRelocations = 0;
	if ( !RvaToFileOffsetLargestSpan( pSections, cSections, relocations.VirtualAddress, &ibRelocations ) ||
	     ibRelocations >= cubFile )
		return true;

	const u32 unDelta = unImageBase - k_unRelocationBase;
	const u32 cubAvailable = cubFile - ibRelocations;
	const u32 cubRelocations = relocations.Size < cubAvailable ? relocations.Size : cubAvailable;
	const u32 unChunkEnd = unChunkRva + cubChunk;

	u32 ibBlock = 0;
	u32 cBlocks = 0;
	while ( ibBlock + sizeof( IMAGE_BASE_RELOCATION ) <= cubRelocations && cBlocks++ < 0x10000 )
	{
		const u8 *pubBlock = pubFile + ibRelocations + ibBlock;
		const u32 unPageRva = util::Read32( pubBlock );
		const u32 cubBlock = util::Read32( pubBlock + 4 );
		if ( cubBlock < sizeof( IMAGE_BASE_RELOCATION ) || ibBlock + cubBlock > cubRelocations )
			return false;

		if ( unPageRva + 0x1000 > unChunkRva && unPageRva < unChunkEnd )
		{
			const u32 cEntries = ( cubBlock - sizeof( IMAGE_BASE_RELOCATION ) ) >> 1;
			for ( u32 iEntry = 0; iEntry < cEntries; ++iEntry )
			{
				const u8 *pubEntry = pubBlock + sizeof( IMAGE_BASE_RELOCATION ) + iEntry * 2u;
				const u16 unEntry = static_cast<u16>( pubEntry[0] | ( static_cast<u16>( pubEntry[1] ) << 8 ) );
				if ( ( unEntry >> 12 ) != IMAGE_REL_BASED_HIGHLOW )
					continue;

				const u32 unPatchRva = unPageRva + ( unEntry & 0x0FFFu );
				if ( unPatchRva < unChunkRva || unPatchRva + 4u > unChunkEnd )
					continue;

				u8 *pubValue = pubChunk + unPatchRva - unChunkRva;
				const u32 unValue = util::Read32( pubValue ) - unDelta;
				memcpy( pubValue, &unValue, sizeof( unValue ) );
			}
		}

		ibBlock += cubBlock;
	}
	return true;
}

// @orig: 55 8B EC 83 EC ? 8B 45
bool HashSection( const u8 *pubFile, u32 cubFile, const IMAGE_SECTION_HEADER &section,
                  const IMAGE_SECTION_HEADER *pSections, u32 cSections, const void *pOptionalHeader, bool bPe64,
                  u32 unImageBase32, crypto::hash::Md5_t &md5 ) noexcept
{
	const IMAGE_DATA_DIRECTORY *pIat = GetDataDirectory( pOptionalHeader, bPe64, IMAGE_DIRECTORY_ENTRY_IAT );
	const IMAGE_DATA_DIRECTORY *pExport = GetDataDirectory( pOptionalHeader, bPe64, IMAGE_DIRECTORY_ENTRY_EXPORT );
	const IMAGE_DATA_DIRECTORY *pRelocations =
	    GetDataDirectory( pOptionalHeader, bPe64, IMAGE_DIRECTORY_ENTRY_BASERELOC );

	RangePair_t iatSplit;
	SplitAroundDirectory( pIat->VirtualAddress, pIat->Size, section.VirtualAddress,
	                      section.VirtualAddress + section.SizeOfRawData, iatSplit );

	RangePair_t first;
	RangePair_t second;
	SplitAroundDirectory( pExport->VirtualAddress, pExport->Size, iatSplit.m_rgunStart[0], iatSplit.m_rgunEnd[0],
	                      first );
	SplitAroundDirectory( pExport->VirtualAddress, pExport->Size, iatSplit.m_rgunStart[1], iatSplit.m_rgunEnd[1],
	                      second );

	const u32 rgunStarts[] = { first.m_rgunStart[0], first.m_rgunStart[1], second.m_rgunStart[0],
	                           second.m_rgunStart[1] };
	const u32 rgunEnds[] = { first.m_rgunEnd[0], first.m_rgunEnd[1], second.m_rgunEnd[0], second.m_rgunEnd[1] };

	u8 rgubChunk[4096];
	for ( u32 iRange = 0; iRange < ARRAYSIZE( rgunStarts ); ++iRange )
	{
		if ( rgunEnds[iRange] <= rgunStarts[iRange] )
			continue;

		u32 unRva = rgunStarts[iRange];
		u32 cubLeft = rgunEnds[iRange] - rgunStarts[iRange];
		while ( cubLeft )
		{
			const u32 cubChunk = cubLeft > sizeof( rgubChunk ) ? sizeof( rgubChunk ) : cubLeft;
			const u32 ibFile = section.PointerToRawData + unRva - section.VirtualAddress;
			if ( ibFile > cubFile || cubChunk > cubFile - ibFile )
				return false;

			memcpy( rgubChunk, pubFile + ibFile, cubChunk );
			if ( !bPe64 && !ApplyRelocationsForHash( pubFile, cubFile, pSections, cSections, *pRelocations,
			                                         unImageBase32, unRva, rgubChunk, cubChunk ) )
				return false;

			md5.Update( rgubChunk, cubChunk );
			unRva += cubChunk;
			cubLeft -= cubChunk;
		}
	}
	return true;
}

// @orig: inlined
const IMAGE_SECTION_HEADER *SelectHashSection( const IMAGE_SECTION_HEADER *pSections, u32 cSections ) noexcept
{
	const IMAGE_SECTION_HEADER *pSelected = nullptr;
	u32 cubLargest = 0;
	bool bFoundText = false;
	for ( u32 iSection = 0; iSection < cSections; ++iSection )
	{
		const IMAGE_SECTION_HEADER &section = pSections[iSection];
		const bool bExecutable = ( section.Characteristics & IMAGE_SCN_MEM_EXECUTE ) != 0;

		bool bText = true;
		for ( u32 iChar = 0; iChar < sizeof( k_szTextSection ) - 1; ++iChar )
		{
			if ( section.Name[iChar] != static_cast<unsigned char>( k_szTextSection[iChar] ) )
			{
				bText = false;
				break;
			}
		}

		if ( bText && bExecutable )
		{
			pSelected = &section;
			bFoundText = true;
		}
		if ( !bFoundText && bExecutable && section.SizeOfRawData > cubLargest )
		{
			pSelected = &section;
			cubLargest = section.SizeOfRawData;
		}
	}
	return pSelected;
}

// @orig: 51 53 55 56 8B F1 57 83 BE
bool AppendOverlaySection( IMAGE_SECTION_HEADER *pSections, u32 *pcSections, u32 cubFile,
                           u32 unSectionAlignment ) noexcept
{
	const u32 cSections = *pcSections;
	u32 ibRawEnd = 0;

	// @note / sapdragon: a vectorized loop would reference the crt's __isa_available
#pragma loop( no_vector )
	for ( u32 iSection = 0; iSection < cSections; ++iSection )
	{
		const u32 ibSectionEnd = pSections[iSection].PointerToRawData + pSections[iSection].SizeOfRawData;
		if ( ibSectionEnd > ibRawEnd )
			ibRawEnd = ibSectionEnd;
	}

	if ( !cSections || ibRawEnd >= cubFile )
		return true;
	if ( !unSectionAlignment )
		return false;

	const IMAGE_SECTION_HEADER &last = pSections[cSections - 1];
	u32 cubSpan = last.Misc.VirtualSize;
	if ( cubSpan < last.SizeOfRawData )
		cubSpan = last.SizeOfRawData + unSectionAlignment - 1 -
		          ( last.SizeOfRawData + unSectionAlignment - 1 ) % unSectionAlignment;

	IMAGE_SECTION_HEADER &overlay = pSections[cSections];
	memset( &overlay, 0, sizeof( overlay ) );
	memcpy( overlay.Name, k_szOverlaySection, sizeof( k_szOverlaySection ) );
	overlay.PointerToRawData = ibRawEnd;
	overlay.SizeOfRawData = cubFile - ibRawEnd;
	overlay.VirtualAddress = last.VirtualAddress + cubSpan + unSectionAlignment - 1;
	overlay.VirtualAddress -= overlay.VirtualAddress % unSectionAlignment;
	overlay.Misc.VirtualSize = overlay.SizeOfRawData + unSectionAlignment - 1;
	overlay.Misc.VirtualSize -= overlay.Misc.VirtualSize % unSectionAlignment;
	overlay.Characteristics = IMAGE_SCN_MEM_DISCARDABLE;

	*pcSections = cSections + 1;
	return true;
}

// @orig: 81 EC ? ? ? ? 53 55 56 57 8B BC 24
bool HashNormalizedPeImage( const u8 *pubFile, u32 cubFile, u8 *pubDigest,
                            const NormalizedHashParams_t &params ) noexcept
{
	if ( !pubFile || cubFile < sizeof( IMAGE_DOS_HEADER ) )
		return false;

	IMAGE_DOS_HEADER dos;
	memcpy( &dos, pubFile, sizeof( dos ) );
	if ( dos.e_magic != IMAGE_DOS_SIGNATURE )
		return false;

	const u32 ibNtHeaders = dos.e_lfanew;
	if ( ibNtHeaders > cubFile || 4u + sizeof( IMAGE_FILE_HEADER ) > cubFile - ibNtHeaders )
		return false;
	if ( util::Read32( pubFile + ibNtHeaders ) != IMAGE_NT_SIGNATURE )
		return false;

	const auto *pFileHeader = reinterpret_cast<const IMAGE_FILE_HEADER *>( pubFile + ibNtHeaders + 4 );
	if ( ( pFileHeader->Machine != IMAGE_FILE_MACHINE_I386 && pFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64 ) ||
	     pFileHeader->NumberOfSections > k_cMaxSections || !pFileHeader->SizeOfOptionalHeader )
		return false;

	const u32 ibOptionalHeader = ibNtHeaders + 4u + sizeof( IMAGE_FILE_HEADER );
	if ( ibOptionalHeader > cubFile || pFileHeader->SizeOfOptionalHeader > cubFile - ibOptionalHeader )
		return false;

	u8 rgubOptionalHeader[sizeof( IMAGE_OPTIONAL_HEADER64 )];
	memset( rgubOptionalHeader, 0, sizeof( rgubOptionalHeader ) );
	bool bPe64 = false;
	u32 unImageBase32 = 0;
	u32 unSectionAlignment = 0;
	if ( pFileHeader->SizeOfOptionalHeader == sizeof( IMAGE_OPTIONAL_HEADER64 ) )
	{
		memcpy( rgubOptionalHeader, pubFile + ibOptionalHeader, sizeof( IMAGE_OPTIONAL_HEADER64 ) );
		const auto *pOptional = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64 *>( rgubOptionalHeader );
		if ( pOptional->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC )
			return false;
		bPe64 = true;
		unSectionAlignment = pOptional->SectionAlignment;
		memset( rgubOptionalHeader + offsetof( IMAGE_OPTIONAL_HEADER64, ImageBase ), 0, sizeof( u32 ) );
		memset( rgubOptionalHeader + offsetof( IMAGE_OPTIONAL_HEADER64, ImageBase ) + sizeof( u32 ), 0, sizeof( u32 ) );
	}
	else if ( pFileHeader->SizeOfOptionalHeader == sizeof( IMAGE_OPTIONAL_HEADER32 ) )
	{
		memcpy( rgubOptionalHeader, pubFile + ibOptionalHeader, sizeof( IMAGE_OPTIONAL_HEADER32 ) );
		const auto *pOptional = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32 *>( rgubOptionalHeader );
		if ( pOptional->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC )
			return false;
		unImageBase32 = params.m_unLoadedBase32 ? params.m_unLoadedBase32 : pOptional->ImageBase;
		unSectionAlignment = pOptional->SectionAlignment;
		memset( rgubOptionalHeader + offsetof( IMAGE_OPTIONAL_HEADER32, ImageBase ), 0, sizeof( u32 ) );
	}
	else
	{
		return false;
	}

	const u32 ibSections = ibOptionalHeader + pFileHeader->SizeOfOptionalHeader;
	const u32 cubSections = pFileHeader->NumberOfSections * sizeof( IMAGE_SECTION_HEADER );
	if ( ibSections > cubFile || cubSections > cubFile - ibSections )
		return false;

	IMAGE_SECTION_HEADER rgSections[k_cMaxSections + 1];
	memcpy( rgSections, pubFile + ibSections, cubSections );

	u32 cSections = pFileHeader->NumberOfSections;
	if ( params.m_bAppendOverlaySection &&
	     !AppendOverlaySection( rgSections, &cSections, cubFile, unSectionAlignment ) )
		return false;

	const IMAGE_SECTION_HEADER *pSelected = SelectHashSection( rgSections, cSections );
	if ( !pSelected || !pSelected->PointerToRawData || !pSelected->SizeOfRawData )
		return false;

	crypto::hash::Md5_t md5;
	md5.Update( reinterpret_cast<const u8 *>( &dos ), sizeof( dos ) );
	md5.Update( reinterpret_cast<const u8 *>( pFileHeader ), sizeof( IMAGE_FILE_HEADER ) );
	md5.Update( rgubOptionalHeader, pFileHeader->SizeOfOptionalHeader );

	// @note / sapdragon: the overlay section only takes part in the selection, its metadata is not on disk
	for ( u32 iSection = 0; iSection < pFileHeader->NumberOfSections; ++iSection )
	{
		md5.Update( rgSections[iSection].Name, 8 );
		md5.Update( reinterpret_cast<const u8 *>( &rgSections[iSection].VirtualAddress ), 4 );
		md5.Update( reinterpret_cast<const u8 *>( &rgSections[iSection].SizeOfRawData ), 4 );
	}

	if ( !HashSection( pubFile, cubFile, *pSelected, rgSections, cSections, rgubOptionalHeader, bPe64, unImageBase32,
	                   md5 ) )
		return false;

	md5.Final( pubDigest );
	return true;
}

} // namespace vac::pe
