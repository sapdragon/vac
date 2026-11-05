// @binary: 8d88e017
#include "internal/pe_reader.hpp"
#include "core/vac_util.hpp"
#include "crt/intrinsics.hpp"
#include "file/file.hpp"
#include "internal/process_context.hpp"
#include "pe/pe.hpp"
#include "util/strings.hpp"

namespace vac::workers::process_memory_map
{

namespace
{

constexpr u32 k_unValveStubMagic = 0x564C56;

// @note / sapdragon: strncmp, but it stops as soon as the section name ends
// @orig: 56 33 F6 57 8B FA
int CompareName( const char *pszName, const char *pszOther, u32 cchMax ) noexcept
{
	for ( u32 iChar = 0; iChar < cchMax; ++iChar )
	{
		const u8 unChar = static_cast<u8>( pszName[iChar] );
		if ( !unChar || unChar != static_cast<u8>( pszOther[iChar] ) )
			return unChar - static_cast<u8>( pszOther[iChar] );
	}
	return 0;
}

} // namespace

// @orig: 53 33 DB 56 8B F1
CPeReader::CPeReader( const SystemImports_t *pImports ) noexcept
    : m_pImports( pImports ), m_ulWindowOffset( 0 ), m_ibCursor( 0 ), m_cubValid( 0 ), m_hFile( INVALID_HANDLE_VALUE ),
      m_hProcess( nullptr ), m_ulRemoteBase( 0 ), m_ulRelocationDelta( 0 ), m_bPe64( false ), m_pSections( nullptr ),
      m_pubRelocations( nullptr ), m_cubRelocations( 0 ), m_cubSectionLeft( 0 ), m_unSectionRva( 0 ),
      m_ibRelocationCursor( 0 )
{
}

// @orig: 83 B9 ? ? ? ? ? 0F 95 C0
bool CPeReader::IsFile() const noexcept
{
	return m_hFile != INVALID_HANDLE_VALUE;
}

// @orig: 56 8B F1 8B 86
void CPeReader::CloseSource() noexcept
{
	if ( m_hFile != INVALID_HANDLE_VALUE )
	{
		m_pImports->CloseHandle( m_hFile );
		m_hFile = INVALID_HANDLE_VALUE;
	}
	m_cubValid = 0;
	m_ulWindowOffset = 0;
	m_ibCursor = 0;
	m_hProcess = nullptr;
}

// @orig: 56 8B F1 E8
bool CPeReader::AttachFile( HANDLE hFile ) noexcept
{
	CloseSource();
	m_hFile = hFile;
	return m_hFile != INVALID_HANDLE_VALUE;
}

// @note / sapdragon: the source is always a file or the handle from OpenProcess, so valve's third branch that
// memcpys from a raw pointer in this process and its range limit can't run here. left out
// @orig: 51 51 53 55 8B 6C 24
u8 *CPeReader::ReadChunk( u32 cub ) noexcept
{
	if ( cub > k_cubPage )
		return nullptr;

	u32 ibCursor = m_ibCursor;
	const u32 cubValid = m_cubValid;
	if ( ibCursor + cub >= cubValid )
	{
		u32 ibFill = 0;
		u32 cubWanted = sizeof( m_rgubWindow );
		if ( ibCursor + cub == cubValid )
		{
			if ( cubValid == sizeof( m_rgubWindow ) )
			{
				memcpy( m_rgubWindow, m_rgubWindow + k_cubPage, k_cubPage );
				m_ulWindowOffset += k_cubPage;
				ibFill = k_cubPage;
				m_ibCursor -= k_cubPage;
				ibCursor = m_ibCursor;
			}
			cubWanted = ibFill;
		}
		else if ( cubValid )
		{
			if ( cubValid < sizeof( m_rgubWindow ) )
				return nullptr;

			memcpy( m_rgubWindow, m_rgubWindow + k_cubPage, k_cubPage );
			m_ulWindowOffset += k_cubPage;
			ibFill = k_cubPage;
			cubWanted = k_cubPage;
			m_ibCursor -= k_cubPage;
		}

		if ( cubWanted )
		{
			u32 cubGot;
			if ( IsFile() )
			{
				DWORD cubRead = 0;
				m_pImports->ReadFile( m_hFile, m_rgubWindow + ibFill, cubWanted, &cubRead, nullptr );
				cubGot = cubRead;
			}
			else
			{
				const u64 ulAddress = m_ulWindowOffset + m_ulRemoteBase + ibFill;
				u64 cubRead = 0;
				ReadVirtualMemory( m_pImports, m_hProcess, ulAddress, m_rgubWindow + ibFill, cubWanted, &cubRead );
				cubGot = static_cast<u32>( cubRead );
				if ( !cubRead && cubWanted > k_cubPage )
				{
					ReadVirtualMemory( m_pImports, m_hProcess, ulAddress, m_rgubWindow + ibFill, k_cubPage, &cubRead );
					cubGot = static_cast<u32>( cubRead );
					if ( !cubRead )
						return nullptr;
				}
			}
			ibCursor = m_ibCursor;
			m_cubValid = cubGot + ibFill;
		}

		if ( ibCursor + cub > m_cubValid )
			return nullptr;
	}

	m_ibCursor = ibCursor + cub;
	return m_rgubWindow + ibCursor;
}

// @orig: 51 51 55 56 33 F6
bool CPeReader::Read( void *pOutput, u32 cub ) noexcept
{
	u32 ibDone = 0;
	if ( !cub )
		return true;

	do
	{
		u32 cubChunk = cub - ibDone;
		if ( cubChunk > k_cubPage )
			cubChunk = k_cubPage;

		const u8 *pubChunk = ReadChunk( cubChunk );
		if ( !pubChunk )
			return false;

		memcpy( static_cast<u8 *>( pOutput ) + ibDone, pubChunk, cubChunk );
		ibDone += cubChunk;
	} while ( ibDone != cub );
	return true;
}

// @orig: 55 8B EC 83 EC ? 56 57
bool CPeReader::Seek( u32 ibOffset ) noexcept
{
	if ( m_ulWindowOffset + m_ibCursor == ibOffset )
		return true;

	if ( ibOffset < m_ulWindowOffset || ibOffset >= m_ulWindowOffset + m_cubValid )
	{
		m_ibCursor = ibOffset % k_cubPage;
		m_ulWindowOffset = ibOffset - m_ibCursor;
		m_cubValid = 0;
		if ( IsFile() && m_pImports->SetFilePointer( m_hFile, static_cast<LONG>( m_ulWindowOffset ), nullptr,
		                                             FILE_BEGIN ) != static_cast<DWORD>( m_ulWindowOffset ) )
		{
			CloseSource();
			return false;
		}
		return true;
	}

	m_ibCursor = ibOffset - static_cast<u32>( m_ulWindowOffset );
	return true;
}

// @orig: 53 0F B7 99
const IMAGE_SECTION_HEADER *CPeReader::FindSectionByName( const char *pszName ) const noexcept
{
	const u32 cSections = m_FileHeaderWithOverlay.NumberOfSections;
	for ( u32 iSection = 0; iSection < cSections; ++iSection )
	{
		if ( CompareName( reinterpret_cast<const char *>( m_pSections[iSection].Name ), pszName,
		                  IMAGE_SIZEOF_SHORT_NAME ) == 0 )
			return &m_pSections[iSection];
	}
	return nullptr;
}

// @orig: 83 EC ? 53 55 56 57 BD
EScanStatus CPeReader::ParseHeaders() noexcept
{
	if ( !Read( &m_DosHeader, sizeof( m_DosHeader ) ) )
		return EScanStatus::ReadFailed;
	if ( m_DosHeader.e_magic != IMAGE_DOS_SIGNATURE )
		return EScanStatus::BadImage;

	if ( !Read( m_rgubDosStub, sizeof( m_rgubDosStub ) ) )
		return EScanStatus::ReadFailed;

	if ( !Seek( static_cast<u32>( m_DosHeader.e_lfanew ) ) )
		return EScanStatus::SeekFailed;

	u32 unSignature;
	if ( !Read( &unSignature, sizeof( unSignature ) ) )
		return EScanStatus::ReadFailed;
	if ( unSignature != IMAGE_NT_SIGNATURE )
		return EScanStatus::BadImage;

	if ( !Read( &m_FileHeader, sizeof( m_FileHeader ) ) )
		return EScanStatus::ReadFailed;
	memcpy( &m_FileHeaderWithOverlay, &m_FileHeader, sizeof( m_FileHeader ) );

	if ( ( m_FileHeaderWithOverlay.Machine != IMAGE_FILE_MACHINE_I386 &&
	       m_FileHeaderWithOverlay.Machine != IMAGE_FILE_MACHINE_AMD64 ) ||
	     m_FileHeaderWithOverlay.NumberOfSections > pe::k_cMaxSections )
		return EScanStatus::BadImage;

	const u16 cubOptional = m_FileHeaderWithOverlay.SizeOfOptionalHeader;
	if ( cubOptional == sizeof( m_Optional64 ) )
	{
		if ( !Read( &m_Optional64, sizeof( m_Optional64 ) ) )
			return EScanStatus::ReadFailed;
		if ( m_Optional64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC )
			return EScanStatus::BadOptionalHeader;
		m_bPe64 = true;
	}
	else if ( cubOptional == sizeof( m_Optional32 ) )
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

	// @note / sapdragon: one more slot than valve, which grows the array for .extra later
	const u32 cSections = m_FileHeaderWithOverlay.NumberOfSections;
	m_pSections =
	    static_cast<IMAGE_SECTION_HEADER *>( util::HeapAlloc( sizeof( IMAGE_SECTION_HEADER ) * ( cSections + 1 ) ) );
	for ( u32 iSection = 0; iSection < cSections; ++iSection )
	{
		if ( !Read( &m_pSections[iSection], sizeof( IMAGE_SECTION_HEADER ) ) )
			return EScanStatus::ReadFailed;
	}

	return EScanStatus::Ok;
}

// @orig: 53 56 57 8B D9 E8
void CPeReader::AttachProcess( u64 ulBase, HANDLE hProcess ) noexcept
{
	Release();
	CloseSource();
	m_ulRemoteBase = ulBase;
	m_hProcess = hProcess;
}

// @orig: 51 56 57 8B F1
EScanStatus CPeReader::ParseProcessImage( u64 ulBase, HANDLE hProcess ) noexcept
{
	Release();
	AttachProcess( ulBase, hProcess );

	const EScanStatus eStatus = ParseHeaders();
	if ( eStatus != EScanStatus::Ok )
	{
		Release();
		return eStatus;
	}
	return EScanStatus::Ok;
}

// @note / sapdragon: only the file path gets ".extra", memory has no overlay. it never gets hashed, the reason it
// exists is that LoadRelocations can find its table in it
// @orig: 51 53 55 56 8B F1 57 83 BE
EScanStatus CPeReader::ParseFile() noexcept
{
	if ( !IsFile() )
		return EScanStatus::NoFile;

	const EScanStatus eStatus = ParseHeaders();
	if ( eStatus != EScanStatus::Ok )
	{
		Release();
		return eStatus;
	}

	u32 cSections = m_FileHeaderWithOverlay.NumberOfSections;
	const u32 cubFile = file::GetFileSizeOrZero( m_pImports, m_hFile );
	const u32 unAlignment = m_bPe64 ? m_Optional64.SectionAlignment : m_Optional32.SectionAlignment;
	// @note / sapdragon: false means overlay plus zero alignment, where valve divides by zero and dies. we treat it as
	// a bad image so the caller falls back to the raw hash
	if ( !pe::AppendOverlaySection( m_pSections, &cSections, cubFile, unAlignment ) )
	{
		Release();
		return EScanStatus::BadOptionalHeader;
	}
	m_FileHeaderWithOverlay.NumberOfSections = static_cast<WORD>( cSections );
	return EScanStatus::Ok;
}

// @note / sapdragon: valve's version also frees a few arrays that nothing in this binary ever fills
// @orig: 53 56 57 8B F1
void CPeReader::Release() noexcept
{
	CloseSource();
	util::HeapFree( m_pSections );
	util::HeapFree( m_pubRelocations );
	m_pSections = nullptr;
	m_pubRelocations = nullptr;
	m_cubRelocations = 0;
	m_ulRelocationDelta = 0;
	m_bPe64 = false;
}

// @orig: 51 56 8B F1 57 80 BE
bool CPeReader::LoadRelocations() noexcept
{
	const IMAGE_DATA_DIRECTORY &directory =
	    *pe::GetDataDirectory( m_bPe64 ? static_cast<const void *>( &m_Optional64 ) : &m_Optional32, m_bPe64,
	                           IMAGE_DIRECTORY_ENTRY_BASERELOC );
	m_cubRelocations = directory.Size;
	if ( !m_cubRelocations )
		return true;

	const IMAGE_SECTION_HEADER *pSection =
	    pe::FindSectionByRva( m_pSections, m_FileHeaderWithOverlay.NumberOfSections, directory.VirtualAddress );
	u32 cubToFile = 0;
	if ( pSection && IsFile() )
		cubToFile = pSection->VirtualAddress - pSection->PointerToRawData;

	if ( !Seek( directory.VirtualAddress - cubToFile ) )
		return false;

	m_pubRelocations = static_cast<u8 *>( util::HeapAlloc( m_cubRelocations ) );
	return Read( m_pubRelocations, m_cubRelocations );
}

// @orig: 8B 81 ? ? ? ? 0B 81 ? ? ? ? 74 ? B0
bool CPeReader::IsRelocated() const noexcept
{
	if ( m_ulRelocationDelta )
		return true;
	if ( IsFile() )
		return false;
	return m_ulRemoteBase != GetImageBase();
}

// @note / sapdragon: pe::ApplyRelocationsForHash is not this. valve fails on an unknown type and patches a dword that
// crosses the chunk end, the overflow sits in the window and goes into the next chunk's hash. a bad block size is not
// checked either, it hangs or faults just like the original
// @orig: 51 51 8B 44 24
bool CPeReader::ApplyRelocations( u8 *pubChunk, u32 unChunkRva, u32 cubChunk ) noexcept
{
	const u32 unChunkEnd = unChunkRva + cubChunk;
	if ( m_bPe64 )
		return false;

	u32 ibBlock = m_ibRelocationCursor;
	while ( ibBlock < m_cubRelocations )
	{
		const auto *punBlock = reinterpret_cast<const u32 *>( m_pubRelocations + ibBlock );
		const u32 unPageRva = punBlock[0];
		if ( unPageRva >= unChunkEnd )
			break;

		const auto *punEntry = reinterpret_cast<const u16 *>( punBlock + 2 );
		const i32 cEntries = static_cast<i32>( ( punBlock[1] - sizeof( IMAGE_BASE_RELOCATION ) ) >> 1 );
		if ( unPageRva + k_cubPage > unChunkRva )
		{
			for ( i32 iEntry = 0; iEntry < cEntries; ++iEntry )
			{
				const u32 unEntry = punEntry[iEntry];
				const u32 unPatchRva = unPageRva + ( unEntry & 0xFFF );
				if ( unPatchRva < unChunkRva )
					continue;
				if ( unPatchRva >= unChunkEnd )
					return true;

				const u32 unType = unEntry >> 12;
				if ( unType == IMAGE_REL_BASED_ABSOLUTE )
					continue;
				if ( unType != IMAGE_REL_BASED_HIGHLOW )
					return false;

				u8 *pubValue = pubChunk + ( unPatchRva - unChunkRva );
				const u32 unValue = util::Read32( pubValue ) - static_cast<u32>( m_ulRelocationDelta );
				memcpy( pubValue, &unValue, sizeof( unValue ) );
			}
		}

		ibBlock += punBlock[1];
		m_ibRelocationCursor = ibBlock;
	}
	return true;
}

// @orig: 55 8B EC 83 EC ? 8B 45
void CPeReader::HashRangeAroundDirectories( const u8 *pubChunk, u32 unChunkRva, u32 cubChunk,
                                            crypto::hash::Md5_t &md5 ) const noexcept
{
	const void *pOptional = m_bPe64 ? static_cast<const void *>( &m_Optional64 ) : &m_Optional32;
	const IMAGE_DATA_DIRECTORY &iat = *pe::GetDataDirectory( pOptional, m_bPe64, IMAGE_DIRECTORY_ENTRY_IAT );
	const IMAGE_DATA_DIRECTORY &exports = *pe::GetDataDirectory( pOptional, m_bPe64, IMAGE_DIRECTORY_ENTRY_EXPORT );

	pe::RangePair_t iatSplit;
	pe::SplitAroundDirectory( iat.VirtualAddress, iat.Size, unChunkRva, unChunkRva + cubChunk, iatSplit );

	pe::RangePair_t first;
	pe::RangePair_t second;
	pe::SplitAroundDirectory( exports.VirtualAddress, exports.Size, iatSplit.m_rgunStart[0], iatSplit.m_rgunEnd[0],
	                          first );
	pe::SplitAroundDirectory( exports.VirtualAddress, exports.Size, iatSplit.m_rgunStart[1], iatSplit.m_rgunEnd[1],
	                          second );

	const u32 rgunStarts[4] = { first.m_rgunStart[0], first.m_rgunStart[1], second.m_rgunStart[0],
	                            second.m_rgunStart[1] };
	const u32 rgunEnds[4] = { first.m_rgunEnd[0], first.m_rgunEnd[1], second.m_rgunEnd[0], second.m_rgunEnd[1] };
	for ( u32 iRange = 0; iRange < 4; ++iRange )
	{
		if ( rgunEnds[iRange] > rgunStarts[iRange] )
			md5.Update( pubChunk + rgunStarts[iRange] - unChunkRva, rgunEnds[iRange] - rgunStarts[iRange] );
	}
}

// @orig: 80 B9 ? ? ? ? ? 74 ? 8B 81 ? ? ? ? 8B 91
u64 CPeReader::GetImageBase() const noexcept
{
	return m_bPe64 ? m_Optional64.ImageBase : m_Optional32.ImageBase;
}

// @orig: 51 53 8B 5C 24
bool CPeReader::BeginSection( const IMAGE_SECTION_HEADER &section ) noexcept
{
	if ( IsRelocated() )
	{
		if ( !m_pubRelocations && !LoadRelocations() )
			return false;
		if ( !m_ulRelocationDelta )
			m_ulRelocationDelta = m_ulRemoteBase - GetImageBase();
	}

	if ( !Seek( IsFile() ? section.PointerToRawData : section.VirtualAddress ) )
		return false;

	m_ibRelocationCursor = 0;
	m_unSectionRva = section.VirtualAddress;
	m_cubSectionLeft = section.SizeOfRawData;
	return true;
}

// @orig: 51 51 53 55 56 8B F1
bool CPeReader::HashNextChunk( crypto::hash::Md5_t &md5 ) noexcept
{
	u32 cubChunk = m_cubSectionLeft;
	if ( !cubChunk )
		return false;
	if ( static_cast<i32>( cubChunk ) > static_cast<i32>( k_cubPage ) )
		cubChunk = k_cubPage;

	u8 *pubChunk = ReadChunk( cubChunk );
	if ( !pubChunk )
		return false;
	if ( IsRelocated() && !m_bPe64 && !ApplyRelocations( pubChunk, m_unSectionRva, cubChunk ) )
		return false;

	HashRangeAroundDirectories( pubChunk, m_unSectionRva, cubChunk, md5 );

	m_unSectionRva += cubChunk;
	m_cubSectionLeft -= cubChunk;
	return m_cubSectionLeft != 0;
}

// @orig: 56 FF 74 24 ? 8B F1 FF 74 24
bool CPeReader::HashSection( const IMAGE_SECTION_HEADER &section, crypto::hash::Md5_t &md5 ) noexcept
{
	if ( !BeginSection( section ) )
		return false;

	while ( HashNextChunk( md5 ) )
	{
	}
	return m_cubSectionLeft == 0;
}

// @note / sapdragon: valve's hash context can also do a CRC, and this function has a raw mode that keeps the load
// address in the hash. both callers always pass plain MD5 and normalized
// @orig: 81 EC ? ? ? ? 53 55 56 57 8B BC 24
bool CPeReader::HashImage( u8 *pubDigest ) noexcept
{
	crypto::hash::Md5_t md5;

	const u64 ulBase = IsFile() ? GetImageBase() : m_ulRemoteBase;
	m_ulRelocationDelta = ulBase - pe::k_unRelocationBase;

	md5.Update( reinterpret_cast<const u8 *>( &m_DosHeader ), sizeof( m_DosHeader ) );
	md5.Update( reinterpret_cast<const u8 *>( &m_FileHeader ), sizeof( m_FileHeader ) );

	IMAGE_OPTIONAL_HEADER64 optional64;
	IMAGE_OPTIONAL_HEADER32 optional32;
	memcpy( &optional64, &m_Optional64, sizeof( optional64 ) );
	memcpy( &optional32, &m_Optional32, sizeof( optional32 ) );
	optional64.ImageBase = 0;
	optional32.ImageBase = 0;
	if ( m_bPe64 )
		md5.Update( reinterpret_cast<const u8 *>( &optional64 ), sizeof( optional64 ) );
	else
		md5.Update( reinterpret_cast<const u8 *>( &optional32 ), sizeof( optional32 ) );

	const u32 cSections = m_FileHeaderWithOverlay.NumberOfSections;
	if ( !cSections )
		return false;

	for ( u32 iSection = 0; iSection < cSections && iSection < m_FileHeader.NumberOfSections; ++iSection )
	{
		const IMAGE_SECTION_HEADER &section = m_pSections[iSection];
		md5.Update( section.Name, IMAGE_SIZEOF_SHORT_NAME );
		md5.Update( reinterpret_cast<const u8 *>( &section.VirtualAddress ), sizeof( section.VirtualAddress ) );
		md5.Update( reinterpret_cast<const u8 *>( &section.SizeOfRawData ), sizeof( section.SizeOfRawData ) );
	}

	const IMAGE_SECTION_HEADER *pSelected = pe::SelectHashSection( m_pSections, cSections );
	if ( !pSelected || !HashSection( *pSelected, md5 ) )
		return false;

	md5.Final( pubDigest );
	return true;
}

bool CPeReader::HasValveStub() const noexcept
{
	return util::Read32( m_rgubDosStub ) == k_unValveStubMagic && util::Read32( m_rgubDosStub + 4 ) == 1 &&
	       util::Read32( m_rgubDosStub + 8 ) != 0;
}

u32 CPeReader::GetSizeOfImage() const noexcept
{
	return m_bPe64 ? m_Optional64.SizeOfImage : m_Optional32.SizeOfImage;
}

} // namespace vac::workers::process_memory_map
