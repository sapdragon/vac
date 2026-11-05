// @binary: 2023d8c3
#include "internal/pe_file.hpp"
#include "internal/string_table.hpp"
#include "core/vac_util.hpp"
#include "crt/intrinsics.hpp"
#include "file/file.hpp"
#include "pe/pe.hpp"

namespace vac::workers::driver_inventory
{

namespace
{

constexpr u32 k_cubPage = 0x1000;
constexpr char k_szOverlaySection[] = ".extra";

} // namespace

// @orig: 53 33 DB 56 8B F1
void CPeFile::Init( const SystemImports_t *pImports ) noexcept
{
	m_pImports = pImports;
	m_hFile = INVALID_HANDLE_VALUE;
	m_cubValid = 0;
	m_ulWindowBase = 0;
	m_ibCursor = 0;
	m_pSections = nullptr;
	m_pubRelocations = nullptr;
	m_cubRelocations = 0;
	m_ulRelocationDelta = 0;
	m_bPe64 = false;
}

// @orig: 56 8B F1 8B 86
void CPeFile::Close() noexcept
{
	if ( m_hFile != INVALID_HANDLE_VALUE )
	{
		m_pImports->CloseHandle( m_hFile );
		m_hFile = INVALID_HANDLE_VALUE;
	}
	m_cubValid = 0;
	m_ulWindowBase = 0;
	m_ibCursor = 0;
}

// @orig: 56 8B F1 E8
bool CPeFile::Attach( HANDLE hFile ) noexcept
{
	Close();
	m_hFile = hFile;
	m_szName[0] = 0;
	return m_hFile != INVALID_HANDLE_VALUE;
}

// @orig: inlined
void CPeFile::SlideWindow() noexcept
{
	memcpy( m_rgubWindow, m_rgubWindow + k_cubPage, k_cubPage );
	m_ulWindowBase += k_cubPage;
	m_ibCursor -= k_cubPage;
}

// @orig: 51 51 53 55 8B 6C 24
u8 *CPeFile::ReadWindow( u32 cubWanted ) noexcept
{
	if ( cubWanted > k_cubPage )
		return nullptr;

	if ( m_ibCursor + cubWanted >= m_cubValid )
	{
		u32 cubKept = 0;
		u32 cubToRead;
		if ( m_ibCursor + cubWanted == m_cubValid )
		{
			if ( m_cubValid == sizeof( m_rgubWindow ) )
			{
				SlideWindow();
				cubKept = k_cubPage;
			}
			cubToRead = cubKept;
		}
		else if ( m_cubValid == 0 )
		{
			cubToRead = sizeof( m_rgubWindow );
		}
		else
		{
			if ( m_cubValid < sizeof( m_rgubWindow ) )
				return nullptr;
			SlideWindow();
			cubKept = k_cubPage;
			cubToRead = k_cubPage;
		}

		if ( cubToRead )
		{
			// @note / sapdragon: the return value is ignored, only the count matters
			DWORD cubRead = 0;
			m_pImports->ReadFile( m_hFile, m_rgubWindow + cubKept, cubToRead, &cubRead, nullptr );
			m_cubValid = cubRead + cubKept;
		}

		if ( m_ibCursor + cubWanted > m_cubValid )
			return nullptr;
	}

	u8 *pubData = m_rgubWindow + m_ibCursor;
	m_ibCursor += cubWanted;
	return pubData;
}

// @orig: 51 51 55 56 33 F6
bool CPeFile::Read( void *pOut, i32 cubWanted ) noexcept
{
	i32 cubDone = 0;
	if ( !cubWanted )
		return true;

	do
	{
		i32 cubChunk = cubWanted - cubDone;
		if ( cubChunk > static_cast<i32>( k_cubPage ) )
			cubChunk = k_cubPage;

		const u8 *pubChunk = ReadWindow( cubChunk );
		if ( !pubChunk )
			return false;

		memcpy( static_cast<u8 *>( pOut ) + cubDone, pubChunk, cubChunk );
		cubDone += cubChunk;
	} while ( cubDone != cubWanted );
	return true;
}

// @orig: 55 8B EC 83 EC ? 56
bool CPeFile::Seek( u32 ibFile ) noexcept
{
	if ( m_ulWindowBase + m_ibCursor == ibFile )
		return true;

	if ( ibFile >= m_ulWindowBase && ibFile < m_ulWindowBase + m_cubValid )
	{
		m_ibCursor = static_cast<u32>( ibFile - m_ulWindowBase );
		return true;
	}

	m_ibCursor = ibFile % k_cubPage;
	m_ulWindowBase = ibFile - m_ibCursor;
	m_cubValid = 0;
	if ( m_hFile != INVALID_HANDLE_VALUE && m_pImports->SetFilePointer( m_hFile, static_cast<LONG>( m_ulWindowBase ),
	                                                                    nullptr, FILE_BEGIN ) != m_ulWindowBase )
	{
		Close();
		return false;
	}
	return true;
}

// @orig: 83 EC ? 53 55 56 57 BD
EScanStatus CPeFile::ParseHeaders() noexcept
{
	if ( !Read( &m_DosHeader, sizeof( m_DosHeader ) ) )
		return EScanStatus::ReadFailed;
	if ( m_DosHeader.e_magic != IMAGE_DOS_SIGNATURE )
		return EScanStatus::BadImage;
	if ( !Read( m_rgubDosStub, sizeof( m_rgubDosStub ) ) )
		return EScanStatus::ReadFailed;
	if ( !Seek( m_DosHeader.e_lfanew ) )
		return EScanStatus::SeekFailed;

	u32 unSignature;
	if ( !Read( &unSignature, sizeof( unSignature ) ) )
		return EScanStatus::ReadFailed;
	if ( unSignature != IMAGE_NT_SIGNATURE )
		return EScanStatus::BadImage;

	if ( !Read( &m_RawFileHeader, sizeof( m_RawFileHeader ) ) )
		return EScanStatus::ReadFailed;
	memcpy( &m_FileHeader, &m_RawFileHeader, sizeof( m_FileHeader ) );

	if ( ( m_FileHeader.Machine != IMAGE_FILE_MACHINE_I386 && m_FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ) ||
	     m_FileHeader.NumberOfSections > pe::k_cMaxSections )
		return EScanStatus::BadImage;

	if ( m_FileHeader.SizeOfOptionalHeader == sizeof( m_Optional64 ) )
	{
		if ( !Read( &m_Optional64, sizeof( m_Optional64 ) ) )
			return EScanStatus::ReadFailed;
		if ( m_Optional64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC )
			return EScanStatus::BadOptionalHeader;
		m_bPe64 = true;
	}
	else if ( m_FileHeader.SizeOfOptionalHeader == sizeof( m_Optional32 ) )
	{
		if ( !Read( &m_Optional32, sizeof( m_Optional32 ) ) )
			return EScanStatus::ReadFailed;
		if ( m_Optional32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC )
			return EScanStatus::BadOptionalHeader;
	}
	else
	{
		return EScanStatus::BadOptionalHeader;
	}

	const u32 cSections = m_FileHeader.NumberOfSections;
	m_pSections = static_cast<IMAGE_SECTION_HEADER *>( util::HeapAlloc( sizeof( IMAGE_SECTION_HEADER ) * cSections ) );
	for ( u32 iSection = 0; iSection < cSections; ++iSection )
	{
		if ( !Read( &m_pSections[iSection], sizeof( IMAGE_SECTION_HEADER ) ) )
			return EScanStatus::ReadFailed;
	}
	return EScanStatus::Ok;
}

// @orig: 55 8B EC 51 51 56
EScanStatus CPeFile::Open( u32 unVolumeSerial, u64 ulFileId, u32 *punLastError ) noexcept
{
	Reset();

	HANDLE hFile = INVALID_HANDLE_VALUE;
	const EScanStatus eStatus = static_cast<EScanStatus>(
	    file::OpenByVolumeAndId( m_pImports, unVolumeSerial, ulFileId, FILE_GENERIC_READ, &hFile, punLastError ) );
	if ( eStatus != EScanStatus::Ok )
		return eStatus;

	if ( !Attach( hFile ) )
	{
		*punLastError = m_pImports->GetLastError();
		return EScanStatus::OpenFailed;
	}
	return EScanStatus::Ok;
}

// @orig: 51 53 55 56 8B F1 57 83 BE
EScanStatus CPeFile::ParseAndAppendOverlay() noexcept
{
	if ( m_hFile == INVALID_HANDLE_VALUE )
		return EScanStatus::NoFile;

	const EScanStatus eStatus = ParseHeaders();
	if ( eStatus != EScanStatus::Ok )
	{
		Reset();
		return eStatus;
	}

	u32 ibRawEnd = 0;
	for ( u32 iSection = 0; iSection < m_FileHeader.NumberOfSections; ++iSection )
	{
		const u32 ibSectionEnd = m_pSections[iSection].SizeOfRawData + m_pSections[iSection].PointerToRawData;
		if ( ibSectionEnd > ibRawEnd )
			ibRawEnd = ibSectionEnd;
	}

	const u32 cubFile = file::GetFileSizeOrZero( m_pImports, m_hFile );
	const u32 unAlignment = m_bPe64 ? m_Optional64.SectionAlignment : m_Optional32.SectionAlignment;
	if ( ibRawEnd < cubFile )
	{
		// @note / sapdragon: not pe::AppendOverlaySection. this one reads before the array with zero sections and
		// faults on a zero alignment, valve never checks either
		++m_FileHeader.NumberOfSections;
		const u32 cubOverlay = cubFile - ibRawEnd;
		m_pSections = static_cast<IMAGE_SECTION_HEADER *>(
		    Reallocate( m_pSections, sizeof( IMAGE_SECTION_HEADER ) * m_FileHeader.NumberOfSections ) );

		IMAGE_SECTION_HEADER &overlay = m_pSections[m_FileHeader.NumberOfSections - 1];
		const IMAGE_SECTION_HEADER &last = m_pSections[m_FileHeader.NumberOfSections - 2];

		u32 cubSpan = last.Misc.VirtualSize;
		if ( cubSpan < last.SizeOfRawData )
			cubSpan = unAlignment + last.SizeOfRawData - 1 - ( unAlignment + last.SizeOfRawData - 1 ) % unAlignment;
		const u32 unEnd = unAlignment + cubSpan + last.VirtualAddress - 1;

		memset( &overlay, 0, sizeof( overlay ) );
		overlay.PointerToRawData = ibRawEnd;
		overlay.Characteristics = IMAGE_SCN_MEM_DISCARDABLE;
		overlay.SizeOfRawData = cubOverlay;
		overlay.VirtualAddress = unEnd - unEnd % unAlignment;
		overlay.Misc.VirtualSize = unAlignment + cubOverlay - 1 - ( unAlignment + cubOverlay - 1 ) % unAlignment;
		memcpy( overlay.Name, k_szOverlaySection, sizeof( k_szOverlaySection ) );
	}
	return EScanStatus::Ok;
}

// @orig: 53 56 57 8B F1
void CPeFile::Reset() noexcept
{
	Close();
	if ( m_pSections )
		util::HeapFree( m_pSections );
	if ( m_pubRelocations )
		util::HeapFree( m_pubRelocations );

	m_ulRelocationDelta = 0;
	m_pSections = nullptr;
	m_pubRelocations = nullptr;
	m_cubRelocations = 0;
	m_bPe64 = false;
}

// @orig: 51 56 8B F1 57 80 BE
bool CPeFile::LoadRelocations() noexcept
{
	const IMAGE_DATA_DIRECTORY &directory = m_bPe64 ? m_Optional64.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
	                                                : m_Optional32.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	m_cubRelocations = directory.Size;
	if ( !m_cubRelocations )
		return true;

	const IMAGE_SECTION_HEADER *pSection =
	    pe::FindSectionByRva( m_pSections, m_FileHeader.NumberOfSections, directory.VirtualAddress );
	u32 unRvaToFile = 0;
	if ( pSection && m_hFile != INVALID_HANDLE_VALUE )
		unRvaToFile = pSection->VirtualAddress - pSection->PointerToRawData;

	if ( !Seek( directory.VirtualAddress - unRvaToFile ) )
		return false;

	m_pubRelocations = static_cast<u8 *>( util::HeapAlloc( m_cubRelocations ) );
	return Read( m_pubRelocations, m_cubRelocations );
}

// @orig: 8B 81 ? ? ? ? 0B 81 ? ? ? ? 74 ? B0
bool CPeFile::IsRelocated() const noexcept
{
	return m_ulRelocationDelta != 0;
}

// @note / sapdragon: not pe::ApplyRelocationsForHash. this one fails on unknown types and patches the window in
// place, so a value crossing the chunk end is already patched when the next chunk reads it
// @orig: 51 51 8B 44 24
bool CPeFile::ApplyRelocations( u8 *pubChunk, u32 unChunkRva, u32 cubChunk, i32 *pibCursor ) noexcept
{
	if ( m_bPe64 )
		return false;

	const u32 unChunkEnd = unChunkRva + cubChunk;
	for ( i32 ibBlock = *pibCursor; ibBlock < m_cubRelocations; ibBlock = *pibCursor )
	{
		const auto *pBlock = reinterpret_cast<const IMAGE_BASE_RELOCATION *>( m_pubRelocations + ibBlock );
		const u32 unPageRva = pBlock->VirtualAddress;
		if ( unPageRva >= unChunkEnd )
			break;

		const i32 cEntries = static_cast<i32>( ( pBlock->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) >> 1 );
		if ( unPageRva + k_cubPage > unChunkRva && cEntries )
		{
			const auto *punEntry = reinterpret_cast<const u16 *>( pBlock + 1 );
			i32 iEntry = 0;
			do
			{
				const u32 unEntry = punEntry[iEntry];
				const u32 unPatchRva = unPageRva + ( unEntry & 0xFFF );
				if ( unPatchRva >= unChunkRva )
				{
					if ( unPatchRva >= unChunkEnd )
						return true;

					const u32 unType = unEntry >> 12;
					if ( unType )
					{
						if ( unType != IMAGE_REL_BASED_HIGHLOW )
							return false;

						u8 *pubValue = pubChunk + unPatchRva - unChunkRva;
						const u32 unValue =
						    *reinterpret_cast<const u32 *>( pubValue ) - static_cast<u32>( m_ulRelocationDelta );
						memcpy( pubValue, &unValue, sizeof( unValue ) );
					}
				}
				++iEntry;
			} while ( iEntry < cEntries );
		}

		*pibCursor = pBlock->SizeOfBlock + ibBlock;
	}
	return true;
}

// @orig: 55 8B EC 83 EC ? 8B 45
void CPeFile::HashRange( const u8 *pubChunk, u32 unRva, u32 cubChunk, crypto::hash::Md5_t &md5 ) noexcept
{
	const IMAGE_DATA_DIRECTORY *pDirectories = m_bPe64 ? m_Optional64.DataDirectory : m_Optional32.DataDirectory;
	const IMAGE_DATA_DIRECTORY &iat = pDirectories[IMAGE_DIRECTORY_ENTRY_IAT];
	const IMAGE_DATA_DIRECTORY &exports = pDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT];

	pe::RangePair_t iatSplit;
	pe::RangePair_t first;
	pe::RangePair_t second;
	pe::SplitAroundDirectory( iat.VirtualAddress, iat.Size, unRva, unRva + cubChunk, iatSplit );
	pe::SplitAroundDirectory( exports.VirtualAddress, exports.Size, iatSplit.m_rgunStart[0], iatSplit.m_rgunEnd[0],
	                          first );
	pe::SplitAroundDirectory( exports.VirtualAddress, exports.Size, iatSplit.m_rgunStart[1], iatSplit.m_rgunEnd[1],
	                          second );

	const u32 rgunStarts[] = { first.m_rgunStart[0], first.m_rgunStart[1], second.m_rgunStart[0],
	                           second.m_rgunStart[1] };
	const u32 rgunEnds[] = { first.m_rgunEnd[0], first.m_rgunEnd[1], second.m_rgunEnd[0], second.m_rgunEnd[1] };
	for ( u32 iRange = 0; iRange < 4; ++iRange )
	{
		if ( rgunEnds[iRange] > rgunStarts[iRange] )
			md5.Update( pubChunk + rgunStarts[iRange] - unRva, rgunEnds[iRange] - rgunStarts[iRange] );
	}
}

// @orig: 80 B9 ? ? ? ? ? 74 ? 8B 81 ? ? ? ? 8B 91
u64 CPeFile::GetImageBase() const noexcept
{
	return m_bPe64 ? m_Optional64.ImageBase : m_Optional32.ImageBase;
}

// @orig: 51 53 8B 5C 24 ? 55 56
bool CPeFile::BeginSectionStream( const IMAGE_SECTION_HEADER &section ) noexcept
{
	if ( IsRelocated() && !m_pubRelocations && !LoadRelocations() )
		return false;

	if ( !Seek( section.PointerToRawData ) )
		return false;

	m_ibRelocationCursor = 0;
	m_unSectionRva = section.VirtualAddress;
	m_cubSectionLeft = section.SizeOfRawData;
	return true;
}

// @orig: 51 51 53 55 56 8B F1
bool CPeFile::HashNextSectionChunk( crypto::hash::Md5_t &md5 ) noexcept
{
	i32 cubChunk = m_cubSectionLeft;
	if ( !cubChunk )
		return false;
	if ( cubChunk > static_cast<i32>( k_cubPage ) )
		cubChunk = k_cubPage;

	u8 *pubChunk = ReadWindow( cubChunk );
	if ( !pubChunk )
		return false;
	if ( IsRelocated() && !m_bPe64 && !ApplyRelocations( pubChunk, m_unSectionRva, cubChunk, &m_ibRelocationCursor ) )
		return false;

	HashRange( pubChunk, m_unSectionRva, cubChunk, md5 );
	m_unSectionRva += cubChunk;
	m_cubSectionLeft -= cubChunk;
	return m_cubSectionLeft != 0;
}

// @orig: 56 FF 74 24 ? 8B F1 FF 74 24
bool CPeFile::HashSectionStream( const IMAGE_SECTION_HEADER &section, crypto::hash::Md5_t &md5 ) noexcept
{
	if ( !BeginSectionStream( section ) )
		return false;

	while ( HashNextSectionChunk( md5 ) )
	{
	}
	return m_cubSectionLeft == 0;
}

// @orig: 81 EC ? ? ? ? 53 55 56
bool CPeFile::HashHeadersAndSelectedSection( crypto::hash::Md5_t &md5, u8 *pubDigest ) noexcept
{
	m_ulRelocationDelta = GetImageBase() - pe::k_unRelocationBase;

	md5.Update( reinterpret_cast<const u8 *>( &m_DosHeader ), sizeof( m_DosHeader ) );
	md5.Update( reinterpret_cast<const u8 *>( &m_RawFileHeader ), sizeof( m_RawFileHeader ) );

	if ( m_bPe64 )
	{
		IMAGE_OPTIONAL_HEADER64 optional;
		memcpy( &optional, &m_Optional64, sizeof( optional ) );
		optional.ImageBase = 0;
		md5.Update( reinterpret_cast<const u8 *>( &optional ), sizeof( optional ) );
	}
	else
	{
		IMAGE_OPTIONAL_HEADER32 optional;
		memcpy( &optional, &m_Optional32, sizeof( optional ) );
		optional.ImageBase = 0;
		md5.Update( reinterpret_cast<const u8 *>( &optional ), sizeof( optional ) );
	}

	if ( !m_FileHeader.NumberOfSections )
		return false;

	// @note / sapdragon: the overlay section can be selected but its metadata is not hashed, it is not on disk
	for ( u32 iSection = 0; iSection < m_RawFileHeader.NumberOfSections; ++iSection )
	{
		const IMAGE_SECTION_HEADER &section = m_pSections[iSection];
		md5.Update( section.Name, sizeof( section.Name ) );
		md5.Update( reinterpret_cast<const u8 *>( &section.VirtualAddress ), sizeof( section.VirtualAddress ) );
		md5.Update( reinterpret_cast<const u8 *>( &section.SizeOfRawData ), sizeof( section.SizeOfRawData ) );
	}

	const IMAGE_SECTION_HEADER *pSelected = pe::SelectHashSection( m_pSections, m_FileHeader.NumberOfSections );
	if ( !pSelected || !HashSectionStream( *pSelected, md5 ) )
		return false;

	md5.Final( pubDigest );
	return true;
}

} // namespace vac::workers::driver_inventory
