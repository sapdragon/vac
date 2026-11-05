// @binary: a8848995
#include "internal/types.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/vac_util.hpp"
#include "crt/intrinsics.hpp"
#include "file/file.hpp"
#include "pe/pe.hpp"
#include "util/encoding.hpp"
#include "util/strings.hpp"

#include <SoftPub.h>

namespace vac::workers::process_file_identity
{

namespace
{

constexpr u32 k_cubReadLimit = 0x1000;
constexpr u32 k_unRsdsSignature = 0x53445352;
constexpr char k_szOverlaySection[] = ".extra";

constexpr GUID k_GuidVerifyV2 = WINTRUST_ACTION_GENERIC_VERIFY_V2;

VAC_LAYOUT_SIZE( WINTRUST_DATA, 48 );

enum class EVisitorState : i32
{
	Root = 0,
	TypeDirectory = 1,
	NameDirectory = 2,
	Done = 3,
};

struct RsdsHeader_t
{
	u32 m_unSignature;
	u8 m_rgubGuid[16];
	u32 m_unAge;
};
VAC_LAYOUT_SIZE( RsdsHeader_t, 24 );

// @note / sapdragon: the original context can also run a checksum, only md5 is ever selected in this binary
struct HashContext_t
{
	crypto::hash::Md5_t m_Md5;
	u8 m_rgubDigest[crypto::hash::k_cubMd5Digest];
	u32 m_cubHashed;
};

struct ResourceEntry_t
{
	u32 m_unName;
	u32 m_unOffset;
};
VAC_LAYOUT_SIZE( ResourceEntry_t, 8 );

#pragma pack( push, 1 )
struct GroupIconEntry_t
{
	u8 m_unWidth;
	u8 m_unHeight;
	u8 m_rgubUnused[10];
	u16 m_unId;
};
VAC_LAYOUT( GroupIconEntry_t, m_unId, 12 );
VAC_LAYOUT_SIZE( GroupIconEntry_t, 14 );

struct GroupIconDirectory_t
{
	u16 m_unReserved;
	u16 m_unType;
	u16 m_cEntries;
	GroupIconEntry_t m_rgEntries[1];
};
VAC_LAYOUT( GroupIconDirectory_t, m_rgEntries, 6 );
#pragma pack( pop )

// @note / sapdragon: valve's are two small classes with a vtable. no virtual here, so a table by hand
struct ResourceVisitor_t;

struct ResourceVisitorTable_t
{
	bool ( *m_pfnEnterDirectory )( ResourceVisitor_t &visitor, const ResourceEntry_t &entry ) noexcept;
	void ( *m_pfnVisitData )( ResourceVisitor_t &visitor, const u8 *pubData, u32 cubData ) noexcept;
	void ( *m_pfnLeaveDirectory )( ResourceVisitor_t &visitor ) noexcept;
};

struct ResourceVisitor_t
{
	const ResourceVisitorTable_t *m_pTable;
	EVisitorState m_eState;
	u32 m_unIconId;
	HashContext_t m_Hash;
};

// @orig: E8 ? ? ? ? 33 C0 6A
void ResetHash( HashContext_t &hash ) noexcept
{
	hash.m_Md5.Init();
	hash.m_cubHashed = 0;
	memset( hash.m_rgubDigest, 0, sizeof( hash.m_rgubDigest ) );
}

// @orig: 51 56 8B F1 57 8B 7C 24
void UpdateHash( HashContext_t &hash, const void *pData, u32 cubData ) noexcept
{
	hash.m_cubHashed += cubData;
	hash.m_Md5.Update( static_cast<const u8 *>( pData ), cubData );
}

const IMAGE_DATA_DIRECTORY &GetDirectory( const PeFile_t &file, u32 iDirectory ) noexcept
{
	const void *pOptionalHeader = file.m_bPe64 ? static_cast<const void *>( &file.m_OptionalHeader64 )
	                                           : static_cast<const void *>( &file.m_OptionalHeader32 );
	return *pe::GetDataDirectory( pOptionalHeader, file.m_bPe64 != 0, iDirectory );
}

// @orig: 83 B9 ? ? ? ? ? 0F 95 C0
bool IsPeFileOpen( const PeFile_t &file ) noexcept
{
	return file.m_hFile != INVALID_HANDLE_VALUE;
}

// @orig: 8B 81 ? ? ? ? 0B 81 ? ? ? ? 74 ? 8B 81
void SetReadRange( PeFile_t &file, u32 unStart, u32 unEnd ) noexcept
{
	if ( file.m_ulMappedBase && ( !file.m_hProcess || file.m_hProcess == INVALID_HANDLE_VALUE ) )
	{
		file.m_ulRangeStart = unStart;
		file.m_ulRangeEnd = unEnd;
	}
}

// @orig: 51 51 53 55 8B 6C 24
u8 *ReadWindow( PeFile_t &file, u32 cubRead ) noexcept
{
	if ( cubRead > k_cubReadLimit )
		return nullptr;

	if ( file.m_ibCursor + cubRead >= file.m_cubWindow )
	{
		u32 ibFill = 0;
		u32 cubFill;
		if ( file.m_ibCursor + cubRead == file.m_cubWindow )
		{
			if ( file.m_cubWindow == sizeof( file.m_rgubWindow ) )
			{
				memcpy( file.m_rgubWindow, file.m_rgubWindow + k_cubReadLimit, k_cubReadLimit );
				ibFill = k_cubReadLimit;
				file.m_ulWindowBase += k_cubReadLimit;
				file.m_ibCursor -= k_cubReadLimit;
			}
			cubFill = ibFill;
		}
		else if ( !file.m_cubWindow )
		{
			cubFill = sizeof( file.m_rgubWindow );
		}
		else
		{
			if ( file.m_cubWindow < sizeof( file.m_rgubWindow ) )
				return nullptr;

			memcpy( file.m_rgubWindow, file.m_rgubWindow + k_cubReadLimit, k_cubReadLimit );
			ibFill = k_cubReadLimit;
			cubFill = k_cubReadLimit;
			file.m_ulWindowBase += k_cubReadLimit;
			file.m_ibCursor -= k_cubReadLimit;
		}

		if ( cubFill )
		{
			u32 cubFilled;
			if ( IsPeFileOpen( file ) )
			{
				DWORD cubGot = 0;
				g_pImports->ReadFile( file.m_hFile, file.m_rgubWindow + ibFill, cubFill, &cubGot, nullptr );
				cubFilled = cubGot;
			}
			else
			{
				// @note / sapdragon: reading a closed file falls through to the memory path. nothing maps an image in
				// this binary, so this faults on the unset base. same in the original
				const u32 unWindowBase = static_cast<u32>( file.m_ulWindowBase );
				const u32 unStart = unWindowBase + ibFill;
				if ( file.m_ulRangeEnd || file.m_ulRangeStart )
				{
					if ( unStart >= file.m_ulRangeStart )
					{
						if ( static_cast<u64>( unStart + cubFill ) > file.m_ulRangeEnd )
							cubFill = static_cast<u32>( file.m_ulRangeEnd ) - unStart;
					}
					else
					{
						cubFill = 0;
					}
				}
				const uptr unSource = ibFill + unWindowBase + static_cast<u32>( file.m_ulMappedBase );
				memcpy( file.m_rgubWindow + ibFill, reinterpret_cast<const void *>( unSource ), cubFill );
				cubFilled = cubFill;
			}
			file.m_cubWindow = cubFilled + ibFill;
		}

		if ( file.m_ibCursor + cubRead > file.m_cubWindow )
			return nullptr;
	}

	u8 *pubResult = file.m_rgubWindow + file.m_ibCursor;
	file.m_ibCursor += cubRead;
	return pubResult;
}

// @orig: 51 51 55 56 33 F6
bool ReadBytes( PeFile_t &file, void *pOutput, u32 cubOutput ) noexcept
{
	u32 ibOutput = 0;
	while ( ibOutput != cubOutput )
	{
		const u32 cubChunk = cubOutput - ibOutput > k_cubReadLimit ? k_cubReadLimit : cubOutput - ibOutput;
		const u8 *pubChunk = ReadWindow( file, cubChunk );
		if ( !pubChunk )
			return false;

		memcpy( static_cast<u8 *>( pOutput ) + ibOutput, pubChunk, cubChunk );
		ibOutput += cubChunk;
	}
	return true;
}

// @orig: 55 8B EC 83 EC ? 56 57 89 4D
bool SeekPeFile( PeFile_t &file, u32 ibOffset ) noexcept
{
	if ( file.m_ulWindowBase + file.m_ibCursor == ibOffset )
		return true;

	if ( ibOffset >= file.m_ulWindowBase && ibOffset < file.m_ulWindowBase + file.m_cubWindow )
	{
		// @note / sapdragon: a seek inside the window does not read again, so bytes patched by relocations stay
		// patched for the next digest. that is why the digests match, do not "fix" it
		file.m_ibCursor = ibOffset - static_cast<u32>( file.m_ulWindowBase );
		return true;
	}

	file.m_ibCursor = ibOffset % k_cubReadLimit;
	const u32 unWindowBase = ibOffset - file.m_ibCursor;
	file.m_ulWindowBase = unWindowBase;
	file.m_cubWindow = 0;
	if ( IsPeFileOpen( file ) &&
	     unWindowBase !=
	         g_pImports->SetFilePointer( file.m_hFile, static_cast<LONG>( unWindowBase ), nullptr, FILE_BEGIN ) )
	{
		ClosePeFile( file );
		return false;
	}
	return true;
}

// @orig: 53 56 57 8B FA 33 C0
bool ExpandSystemPrefix( const wchar_t *pwszPath, wchar_t *pwszOutput ) noexcept
{
	static constexpr wchar_t k_wszNtPrefix[] = L"\\??\\";

	*pwszOutput = 0;

	bool bNtPrefix = true;
	for ( u32 iChar = 0; iChar < 4; ++iChar )
	{
		if ( !pwszPath[iChar] || pwszPath[iChar] != k_wszNtPrefix[iChar] )
		{
			bNtPrefix = false;
			break;
		}
	}
	if ( bNtPrefix )
	{
		CopyWideFixed( pwszOutput, pwszPath + 4, MAX_PATH );
		return true;
	}

	const wchar_t *pwszDirectory;
	u32 cPrefixChars;
	if ( !CompareNoCaseN( pwszPath, L"\\SystemRoot", 11 ) )
	{
		pwszDirectory = g_pSession->m_wszWindowsDirectory;
		cPrefixChars = 11;
	}
	else if ( !CompareNoCaseN( pwszPath, L"\\SystemDirectory", 16 ) )
	{
		pwszDirectory = g_pSession->m_wszSystemDirectory;
		cPrefixChars = 16;
	}
	else if ( !CompareNoCaseN( pwszPath, L"\\windows", 8 ) )
	{
		pwszDirectory = g_pSession->m_wszWindowsDirectory;
		cPrefixChars = 8;
	}
	else
	{
		CopyWideFixed( pwszOutput, pwszPath, MAX_PATH );
		return false;
	}

	CopyWideFixed( pwszOutput, pwszDirectory, MAX_PATH );
	CatWideBounded( pwszOutput, pwszPath + cPrefixChars, MAX_PATH - lstrlenW( pwszOutput ) );
	return true;
}

// @orig: 81 EC ? ? ? ? 53 55 56 57 8B F1
bool OpenWithPrefixFallback( PeFile_t &file, const wchar_t *pwszPath ) noexcept
{
	ClosePeFile( file );

	file.m_hFile = g_pImports->CreateFileW( pwszPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
	                                        FILE_ATTRIBUTE_NORMAL, nullptr );
	wchar_t wszExpanded[MAX_PATH];
	if ( file.m_hFile == INVALID_HANDLE_VALUE && ExpandSystemPrefix( pwszPath, wszExpanded ) )
		file.m_hFile = g_pImports->CreateFileW( wszExpanded, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		                                        FILE_ATTRIBUTE_NORMAL, nullptr );

	util::encoding::WideToUtf8Bounded( g_pImports, pwszPath, file.m_szPath, 259 );
	return file.m_hFile != INVALID_HANDLE_VALUE;
}

// @orig: 56 33 F6 57 8B FA
int CompareN( const char *pszA, const char *pszB, u32 cChars ) noexcept
{
	for ( u32 iChar = 0; iChar < cChars; ++iChar )
	{
		const u8 unChar = static_cast<u8>( pszA[iChar] );
		if ( !unChar || unChar != static_cast<u8>( pszB[iChar] ) )
			return unChar - static_cast<u8>( pszB[iChar] );
	}
	return 0;
}

// @orig: 53 0F B7 99 ? ? ? ? 56
const IMAGE_SECTION_HEADER *FindOverlaySection( const PeFile_t &file ) noexcept
{
	for ( u32 iSection = 0; iSection < file.m_FileHeader.NumberOfSections; ++iSection )
	{
		const IMAGE_SECTION_HEADER &section = file.m_pSections[iSection];
		if ( !CompareN( reinterpret_cast<const char *>( section.Name ), k_szOverlaySection, IMAGE_SIZEOF_SHORT_NAME ) )
			return &section;
	}
	return nullptr;
}

// @orig: 83 EC ? 53 55 56 57 BD
EScanStatus ParseHeaders( PeFile_t &file ) noexcept
{
	SetReadRange( file, 0, k_cubReadLimit );

	if ( !ReadBytes( file, &file.m_DosHeader, sizeof( file.m_DosHeader ) ) )
		return EScanStatus::ReadFailed;
	if ( file.m_DosHeader.e_magic != IMAGE_DOS_SIGNATURE )
		return EScanStatus::BadImage;

	if ( !ReadBytes( file, file.m_rgubDosStub, sizeof( file.m_rgubDosStub ) ) )
		return EScanStatus::ReadFailed;

	if ( !SeekPeFile( file, file.m_DosHeader.e_lfanew ) )
		return EScanStatus::SeekFailed;

	u32 unSignature;
	if ( !ReadBytes( file, &unSignature, sizeof( unSignature ) ) )
		return EScanStatus::ReadFailed;
	if ( unSignature != IMAGE_NT_SIGNATURE )
		return EScanStatus::BadImage;

	if ( !ReadBytes( file, &file.m_OriginalFileHeader, sizeof( file.m_OriginalFileHeader ) ) )
		return EScanStatus::ReadFailed;
	file.m_FileHeader = file.m_OriginalFileHeader;

	if ( ( file.m_FileHeader.Machine != IMAGE_FILE_MACHINE_I386 &&
	       file.m_FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ) ||
	     file.m_FileHeader.NumberOfSections > 64 )
		return EScanStatus::BadImage;

	if ( file.m_FileHeader.SizeOfOptionalHeader == sizeof( file.m_OptionalHeader64 ) )
	{
		if ( !ReadBytes( file, &file.m_OptionalHeader64, sizeof( file.m_OptionalHeader64 ) ) )
			return EScanStatus::ReadFailed;
		if ( file.m_OptionalHeader64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC )
			return EScanStatus::BadOptionalHeader;
		file.m_bPe64 = 1;
	}
	else if ( file.m_FileHeader.SizeOfOptionalHeader == sizeof( file.m_OptionalHeader32 ) )
	{
		if ( !ReadBytes( file, &file.m_OptionalHeader32, sizeof( file.m_OptionalHeader32 ) ) )
			return EScanStatus::ReadFailed;
		if ( file.m_OptionalHeader32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC )
			return EScanStatus::BadOptionalHeader;
	}
	else
	{
		return EScanStatus::BadOptionalHeader;
	}

	const u32 cSections = file.m_FileHeader.NumberOfSections;
	file.m_pSections =
	    static_cast<IMAGE_SECTION_HEADER *>( util::HeapAlloc( sizeof( IMAGE_SECTION_HEADER ) * cSections ) );
	for ( u32 iSection = 0; iSection < cSections; ++iSection )
	{
		if ( !ReadBytes( file, &file.m_pSections[iSection], sizeof( IMAGE_SECTION_HEADER ) ) )
			return EScanStatus::ReadFailed;
	}

	file.m_ulImageBase = file.m_bPe64 ? file.m_OptionalHeader64.ImageBase : file.m_OptionalHeader32.ImageBase;
	SetReadRange( file, 0, 0 );
	return EScanStatus::Ok;
}

u32 GetImageChecksum( const PeFile_t &file ) noexcept
{
	return file.m_bPe64 ? file.m_OptionalHeader64.CheckSum : file.m_OptionalHeader32.CheckSum;
}

// @orig: 51 56 8B F1 57 80 BE
bool LoadRelocations( PeFile_t &file ) noexcept
{
	const IMAGE_DATA_DIRECTORY &directory = GetDirectory( file, IMAGE_DIRECTORY_ENTRY_BASERELOC );
	file.m_cubRelocations = directory.Size;
	if ( !directory.Size )
		return true;

	const IMAGE_SECTION_HEADER *pSection =
	    pe::FindSectionByRva( file.m_pSections, file.m_FileHeader.NumberOfSections, directory.VirtualAddress );
	u32 ibDelta = 0;
	if ( pSection && IsPeFileOpen( file ) )
		ibDelta = pSection->VirtualAddress - pSection->PointerToRawData;

	if ( !SeekPeFile( file, directory.VirtualAddress - ibDelta ) )
		return false;

	file.m_pubRelocations = static_cast<u8 *>( util::HeapAlloc( file.m_cubRelocations ) );
	return ReadBytes( file, file.m_pubRelocations, file.m_cubRelocations );
}

// @orig: 8B 81 ? ? ? ? 0B 81 ? ? ? ? 74 ? B0
bool NeedsRelocation( const PeFile_t &file ) noexcept
{
	if ( file.m_ulRelocationDelta )
		return true;
	if ( IsPeFileOpen( file ) )
		return false;
	if ( file.m_bPe64 )
		return file.m_ulMappedBase != file.m_OptionalHeader64.ImageBase;
	return file.m_ulMappedBase != file.m_OptionalHeader32.ImageBase;
}

// @orig: 51 51 8B 44 24
bool ApplyRelocations( PeFile_t &file, u8 *pubChunk, u32 unRva, u32 cubChunk ) noexcept
{
	if ( file.m_bPe64 )
		return false;

	const u32 unEnd = cubChunk + unRva;
	for ( u32 ibBlock = file.m_ibRelocationCursor; ibBlock < file.m_cubRelocations;
	      file.m_ibRelocationCursor = ibBlock )
	{
		const auto *pBlock = reinterpret_cast<const IMAGE_BASE_RELOCATION *>( file.m_pubRelocations + ibBlock );
		if ( pBlock->VirtualAddress >= unEnd )
			break;

		const auto *punEntries = reinterpret_cast<const u16 *>( pBlock + 1 );
		const i32 cEntries = static_cast<i32>( ( pBlock->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) >> 1 );
		if ( pBlock->VirtualAddress + 0x1000 > unRva )
		{
			for ( i32 iEntry = 0; iEntry < cEntries; ++iEntry )
			{
				const u16 unEntry = punEntries[iEntry];
				const u32 unTarget = pBlock->VirtualAddress + ( unEntry & 0xFFF );
				if ( unTarget < unRva )
					continue;
				if ( unTarget >= unEnd )
					return true;

				const u32 unType = unEntry >> 12;
				if ( !unType )
					continue;
				if ( unType != IMAGE_REL_BASED_HIGHLOW )
					return false;

				// @note / sapdragon: a value crossing the chunk end gets patched too, the window has the room
				auto *punValue = reinterpret_cast<u32 *>( pubChunk + unTarget - unRva );
				++file.m_cRelocationsApplied;
				*punValue -= static_cast<u32>( file.m_ulRelocationDelta );
			}
		}

		ibBlock = pBlock->SizeOfBlock + file.m_ibRelocationCursor;
	}
	return true;
}

// @orig: 55 8B EC 83 EC ? 8B 45
void HashAroundDirectories( const PeFile_t &file, HashContext_t &hash, const u8 *pubChunk, u32 unRva,
                            u32 cubChunk ) noexcept
{
	const IMAGE_DATA_DIRECTORY &iat = GetDirectory( file, IMAGE_DIRECTORY_ENTRY_IAT );
	const IMAGE_DATA_DIRECTORY &exports = GetDirectory( file, IMAGE_DIRECTORY_ENTRY_EXPORT );

	pe::RangePair_t aroundIat;
	pe::RangePair_t rgParts[2];
	pe::SplitAroundDirectory( iat.VirtualAddress, iat.Size, unRva, unRva + cubChunk, aroundIat );
	pe::SplitAroundDirectory( exports.VirtualAddress, exports.Size, aroundIat.m_rgunStart[0], aroundIat.m_rgunEnd[0],
	                          rgParts[0] );
	pe::SplitAroundDirectory( exports.VirtualAddress, exports.Size, aroundIat.m_rgunStart[1], aroundIat.m_rgunEnd[1],
	                          rgParts[1] );

	for ( const pe::RangePair_t &part : rgParts )
	{
		for ( u32 iRange = 0; iRange < 2; ++iRange )
		{
			if ( part.m_rgunEnd[iRange] > part.m_rgunStart[iRange] )
				UpdateHash( hash, pubChunk + part.m_rgunStart[iRange] - unRva,
				            part.m_rgunEnd[iRange] - part.m_rgunStart[iRange] );
		}
	}
}

// @orig: 80 B9 ? ? ? ? ? 74 ? 8B 81 ? ? ? ? 8B 91
u64 GetHeaderImageBase( const PeFile_t &file ) noexcept
{
	return file.m_bPe64 ? file.m_OptionalHeader64.ImageBase : file.m_OptionalHeader32.ImageBase;
}

// @orig: 51 53 8B 5C 24 ? 55 56
bool BeginSectionHash( PeFile_t &file, const IMAGE_SECTION_HEADER &section ) noexcept
{
	if ( NeedsRelocation( file ) )
	{
		if ( !file.m_pubRelocations && !LoadRelocations( file ) )
			return false;
		if ( !file.m_ulRelocationDelta )
			file.m_ulRelocationDelta = file.m_ulMappedBase - GetHeaderImageBase( file );
	}

	if ( !SeekPeFile( file, IsPeFileOpen( file ) ? section.PointerToRawData : section.VirtualAddress ) )
		return false;

	file.m_ibRelocationCursor = 0;
	file.m_unSectionRva = section.VirtualAddress;
	file.m_cubSectionRemaining = section.SizeOfRawData;
	return true;
}

// @orig: 51 51 53 55 56 8B F1
bool HashNextChunk( PeFile_t &file, HashContext_t &hash ) noexcept
{
	if ( !file.m_cubSectionRemaining )
		return false;

	// @note / sapdragon: a signed compare in the original. a size past 2 GB is not clamped and the read then refuses it
	i32 nChunk = static_cast<i32>( file.m_cubSectionRemaining );
	if ( nChunk > static_cast<i32>( k_cubReadLimit ) )
		nChunk = k_cubReadLimit;
	const u32 cubChunk = static_cast<u32>( nChunk );

	u8 *pubChunk = ReadWindow( file, cubChunk );
	if ( !pubChunk )
		return false;
	if ( NeedsRelocation( file ) && !file.m_bPe64 &&
	     !ApplyRelocations( file, pubChunk, file.m_unSectionRva, cubChunk ) )
		return false;

	const u32 unRva = file.m_unSectionRva;
	if ( file.m_bLayoutDigest )
	{
		// @note / sapdragon: this one leaves out the IAT without the 4 extra bytes the other digest skips
		const IMAGE_DATA_DIRECTORY &iat = GetDirectory( file, IMAGE_DIRECTORY_ENTRY_IAT );
		const u32 unIatEnd = iat.VirtualAddress + iat.Size;
		const u32 unCutStart = iat.VirtualAddress > unRva ? iat.VirtualAddress : unRva;
		const u32 unCutEnd = unIatEnd < unRva + cubChunk ? unIatEnd : unRva + cubChunk;
		if ( unCutStart < unCutEnd )
		{
			if ( unCutStart > unRva )
				UpdateHash( hash, pubChunk, unCutStart - unRva );
			if ( unCutEnd < unRva + cubChunk )
				UpdateHash( hash, pubChunk + unCutEnd - unRva, unRva + cubChunk - unCutEnd );
		}
		else
		{
			UpdateHash( hash, pubChunk, cubChunk );
		}
	}
	else
	{
		HashAroundDirectories( file, hash, pubChunk, unRva, cubChunk );
	}

	file.m_unSectionRva += cubChunk;
	file.m_cubSectionRemaining -= cubChunk;
	return file.m_cubSectionRemaining != 0;
}

// @orig: 56 FF 74 24 ? 8B F1 FF 74 24
bool HashSection( PeFile_t &file, const IMAGE_SECTION_HEADER &section, HashContext_t &hash ) noexcept
{
	if ( !BeginSectionHash( file, section ) )
		return false;

	while ( HashNextChunk( file, hash ) )
		;
	return !file.m_cubSectionRemaining;
}

// @orig: 81 EC ? ? ? ? 53 55 56 57 8B BC 24
bool HashImage( PeFile_t &file, HashContext_t &hash, bool bSectionOnly ) noexcept
{
	if ( !file.m_bLayoutDigest )
	{
		const u64 ulBase = IsPeFileOpen( file ) ? GetHeaderImageBase( file ) : file.m_ulMappedBase;

		// @note / sapdragon: the layout digest skips this and reuses the delta of the digest before it
		file.m_ulRelocationDelta = ulBase - pe::k_unRelocationBase;
	}

	if ( !bSectionOnly )
	{
		UpdateHash( hash, &file.m_DosHeader, sizeof( file.m_DosHeader ) );
		UpdateHash( hash, file.m_bLayoutDigest ? &file.m_FileHeader : &file.m_OriginalFileHeader,
		            sizeof( IMAGE_FILE_HEADER ) );

		IMAGE_OPTIONAL_HEADER64 optional64;
		IMAGE_OPTIONAL_HEADER32 optional32;
		memcpy( &optional64, &file.m_OptionalHeader64, sizeof( optional64 ) );
		memcpy( &optional32, &file.m_OptionalHeader32, sizeof( optional32 ) );
		if ( !file.m_bLayoutDigest )
		{
			optional64.ImageBase = 0;
			optional32.ImageBase = 0;
		}

		if ( file.m_bPe64 )
			UpdateHash( hash, &optional64, sizeof( optional64 ) );
		else
			UpdateHash( hash, &optional32, sizeof( optional32 ) );
	}

	if ( !file.m_FileHeader.NumberOfSections )
		return false;

	const IMAGE_SECTION_HEADER *pSelected = nullptr;
	u32 cubLargest = 0;
	bool bFoundText = false;
	for ( u32 iSection = 0; iSection < file.m_FileHeader.NumberOfSections; ++iSection )
	{
		const IMAGE_SECTION_HEADER &section = file.m_pSections[iSection];
		if ( !bSectionOnly && ( iSection < file.m_OriginalFileHeader.NumberOfSections || file.m_bLayoutDigest ) )
		{
			UpdateHash( hash, section.Name, IMAGE_SIZEOF_SHORT_NAME );
			UpdateHash( hash, &section.VirtualAddress, sizeof( section.VirtualAddress ) );
			UpdateHash( hash, &section.SizeOfRawData, sizeof( section.SizeOfRawData ) );
		}

		if ( !CompareN( reinterpret_cast<const char *>( section.Name ), ".text", 5 ) &&
		     ( section.Characteristics & IMAGE_SCN_MEM_EXECUTE ) )
		{
			bFoundText = true;
			pSelected = &section;
		}
		if ( !bFoundText && ( section.Characteristics & IMAGE_SCN_MEM_EXECUTE ) && section.SizeOfRawData > cubLargest )
		{
			pSelected = &section;
			cubLargest = section.SizeOfRawData;
		}
	}

	if ( !pSelected || !HashSection( file, *pSelected, hash ) )
		return false;

	hash.m_Md5.Final( hash.m_rgubDigest );
	return true;
}

// @orig: 83 EC ? 53 55 56 57 8B F1
EScanStatus ParseDebugDirectory( PeFile_t &file ) noexcept
{
	memset( &file.m_DebugDirectory, 0, sizeof( file.m_DebugDirectory ) );
	memset( file.m_rgubPdbGuid, 0, sizeof( file.m_rgubPdbGuid ) );
	memset( file.m_szPdbPath, 0, sizeof( file.m_szPdbPath ) );

	const IMAGE_DATA_DIRECTORY &directory = GetDirectory( file, IMAGE_DIRECTORY_ENTRY_DEBUG );
	if ( !directory.Size )
		return EScanStatus::NoDebugDirectory;

	const IMAGE_SECTION_HEADER *pSection =
	    pe::FindSectionByRva( file.m_pSections, file.m_FileHeader.NumberOfSections, directory.VirtualAddress );
	if ( !pSection )
		return EScanStatus::NoDebugSection;

	u32 ibDelta = 0;
	if ( IsPeFileOpen( file ) )
		ibDelta = pSection->VirtualAddress - pSection->PointerToRawData;
	if ( !SeekPeFile( file, directory.VirtualAddress - ibDelta ) )
		return EScanStatus::SeekFailed;

	SetReadRange( file, pSection->VirtualAddress, pSection->VirtualAddress + pSection->Misc.VirtualSize );

	u32 cubLeft = directory.Size;
	while ( cubLeft >= sizeof( IMAGE_DEBUG_DIRECTORY ) )
	{
		memset( &file.m_DebugDirectory, 0, sizeof( file.m_DebugDirectory ) );
		if ( !ReadBytes( file, &file.m_DebugDirectory, sizeof( file.m_DebugDirectory ) ) )
			break;

		cubLeft -= sizeof( IMAGE_DEBUG_DIRECTORY );
		if ( file.m_DebugDirectory.Type == IMAGE_DEBUG_TYPE_CODEVIEW )
			break;
	}

	if ( file.m_DebugDirectory.Type == IMAGE_DEBUG_TYPE_CODEVIEW &&
	     SeekPeFile( file, file.m_DebugDirectory.AddressOfRawData - ibDelta ) )
	{
		const u32 cubData = file.m_DebugDirectory.SizeOfData;
		u32 unSignature;
		if ( cubData >= sizeof( unSignature ) && ReadBytes( file, &unSignature, sizeof( unSignature ) ) &&
		     unSignature == k_unRsdsSignature && cubData >= sizeof( RsdsHeader_t ) )
		{
			u8 rgubGuidAndAge[20];
			if ( ReadBytes( file, rgubGuidAndAge, sizeof( rgubGuidAndAge ) ) )
			{
				memcpy( file.m_rgubPdbGuid, rgubGuidAndAge, sizeof( file.m_rgubPdbGuid ) );

				u32 cubPath = cubData - sizeof( RsdsHeader_t );
				if ( cubPath > sizeof( file.m_szPdbPath ) )
					cubPath = sizeof( file.m_szPdbPath );
				ReadBytes( file, file.m_szPdbPath, cubPath );
				file.m_szPdbPath[sizeof( file.m_szPdbPath ) - 1] = 0;
			}
		}
	}

	SetReadRange( file, 0, 0 );
	return EScanStatus::Ok;
}

// @orig: 83 EC ? 53 8B 5C 24 ? 55 56 57 8B 7C 24
bool ReadResourceData( PeFile_t &file, u32 ibEntry, u8 **ppubData, u32 *pcubData ) noexcept
{
	*pcubData = 0;
	*ppubData = nullptr;
	if ( !SeekPeFile( file, ibEntry ) )
		return false;

	const u8 *pubEntry = ReadWindow( file, sizeof( IMAGE_RESOURCE_DATA_ENTRY ) );
	if ( !pubEntry )
		return false;

	IMAGE_RESOURCE_DATA_ENTRY entry;
	memcpy( &entry, pubEntry, sizeof( entry ) );
	if ( !entry.Size )
		return false;

	const u32 ibData = pe::RvaToFileOffset( file.m_pSections, file.m_FileHeader.NumberOfSections, entry.OffsetToData );
	if ( ibData == pe::k_unInvalidOffset || !SeekPeFile( file, ibData ) )
		return false;

	*ppubData = static_cast<u8 *>( util::HeapAlloc( entry.Size ) );
	*pcubData = entry.Size;
	if ( !ReadBytes( file, *ppubData, entry.Size ) )
	{
		util::HeapFree( *ppubData );
		*ppubData = nullptr;
		*pcubData = 0;
		return false;
	}
	return true;
}

// @orig: 51 51 53 55 56 57 6A
bool WalkResourceDirectory( PeFile_t &file, ResourceVisitor_t &visitor, u32 ibRoot, u32 ibDirectory ) noexcept
{
	if ( !SeekPeFile( file, ibDirectory ) )
		return false;

	const auto *pPeek =
	    reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY *>( ReadWindow( file, sizeof( IMAGE_RESOURCE_DIRECTORY ) ) );
	if ( !pPeek )
		return false;

	const u32 cubEntries = sizeof( ResourceEntry_t ) * ( pPeek->NumberOfIdEntries + pPeek->NumberOfNamedEntries );
	if ( !SeekPeFile( file, ibDirectory ) )
		return false;

	const u8 *pubDirectory = ReadWindow( file, cubEntries + sizeof( IMAGE_RESOURCE_DIRECTORY ) );
	if ( !pubDirectory )
		return false;

	auto *pDirectory = static_cast<IMAGE_RESOURCE_DIRECTORY *>( util::HeapAlloc( sizeof( IMAGE_RESOURCE_DIRECTORY ) ) );
	memcpy( pDirectory, pubDirectory, sizeof( IMAGE_RESOURCE_DIRECTORY ) );
	auto *pEntries = static_cast<ResourceEntry_t *>( util::HeapAlloc( cubEntries ) );
	memcpy( pEntries, pubDirectory + sizeof( IMAGE_RESOURCE_DIRECTORY ), cubEntries );

	const i32 cEntries = pDirectory->NumberOfIdEntries + pDirectory->NumberOfNamedEntries;
	for ( i32 iEntry = 0; iEntry < cEntries; ++iEntry )
	{
		const ResourceEntry_t &entry = pEntries[iEntry];
		if ( entry.m_unOffset & IMAGE_RESOURCE_DATA_IS_DIRECTORY )
		{
			if ( visitor.m_pTable->m_pfnEnterDirectory( visitor, entry ) )
			{
				WalkResourceDirectory( file, visitor, ibRoot,
				                       ( entry.m_unOffset & ~IMAGE_RESOURCE_DATA_IS_DIRECTORY ) + ibRoot );
				visitor.m_pTable->m_pfnLeaveDirectory( visitor );
			}
		}
		else
		{
			u8 *pubData = nullptr;
			u32 cubData = 0;
			if ( ReadResourceData( file, entry.m_unOffset + ibRoot, &pubData, &cubData ) )
			{
				visitor.m_pTable->m_pfnVisitData( visitor, pubData, cubData );
				util::HeapFree( pubData );
			}
		}
	}

	util::HeapFree( pDirectory );
	util::HeapFree( pEntries );
	return true;
}

// @orig: 51 56 8B F1 B8
bool WalkResources( PeFile_t &file, ResourceVisitor_t &visitor ) noexcept
{
	const IMAGE_DATA_DIRECTORY &directory = GetDirectory( file, IMAGE_DIRECTORY_ENTRY_RESOURCE );
	if ( !directory.Size )
		return false;

	const u32 ibRoot =
	    pe::RvaToFileOffset( file.m_pSections, file.m_FileHeader.NumberOfSections, directory.VirtualAddress );
	if ( ibRoot == pe::k_unInvalidOffset )
		return false;

	return WalkResourceDirectory( file, visitor, ibRoot, ibRoot );
}

// @orig: 83 79 ? ? 75 ? 8B 44 24 ? 83 38 ? 7C ? 66 83 38 ? 75 ? C7 41 ? ? ? ? ? B0 ? EB ? 83 79 ? ? 75 ? C7 41
bool EnterGroupIconDirectory( ResourceVisitor_t &visitor, const ResourceEntry_t &entry ) noexcept
{
	if ( visitor.m_eState == EVisitorState::Root )
	{
		if ( static_cast<i32>( entry.m_unName ) >= 0 &&
		     static_cast<u16>( entry.m_unName ) == reinterpret_cast<uptr>( RT_GROUP_ICON ) )
		{
			visitor.m_eState = EVisitorState::TypeDirectory;
			return true;
		}
	}
	else if ( visitor.m_eState == EVisitorState::TypeDirectory )
	{
		visitor.m_eState = EVisitorState::NameDirectory;
		return true;
	}
	return false;
}

// @orig: 53 8B D9 83 7B
void SelectLargestIcon( ResourceVisitor_t &visitor, const u8 *pubData, u32 cubData ) noexcept
{
	if ( visitor.m_eState == EVisitorState::Done || !pubData ||
	     cubData < offsetof( GroupIconDirectory_t, m_rgEntries ) )
		return;

	const auto *pGroup = reinterpret_cast<const GroupIconDirectory_t *>( pubData );
	const u32 cIcons = pGroup->m_cEntries;
	if ( static_cast<u16>( cubData ) <
	         sizeof( GroupIconEntry_t ) * cIcons + offsetof( GroupIconDirectory_t, m_rgEntries ) ||
	     !cIcons )
		return;

	const GroupIconEntry_t *pLargest = nullptr;
	u32 cLargestPixels = 0;
	for ( u32 iIcon = 0; iIcon < cIcons; ++iIcon )
	{
		const GroupIconEntry_t &icon = pGroup->m_rgEntries[iIcon];
		const u32 cPixels = icon.m_unWidth * icon.m_unHeight;
		if ( cPixels > cLargestPixels )
		{
			cLargestPixels = cPixels;
			pLargest = &icon;
		}
	}

	if ( pLargest )
	{
		visitor.m_unIconId = pLargest->m_unId;
		visitor.m_eState = EVisitorState::Done;
	}
}

// @orig: 8B 41 ? 85 C0 78
void LeaveResourceDirectory( ResourceVisitor_t &visitor ) noexcept
{
	if ( visitor.m_eState == EVisitorState::Root || visitor.m_eState == EVisitorState::TypeDirectory )
		visitor.m_eState = EVisitorState::Root;
	else if ( visitor.m_eState == EVisitorState::NameDirectory )
		visitor.m_eState = EVisitorState::TypeDirectory;
}

// @note / sapdragon: only reachable through the vtable, so the export has no function here and no @orig can resolve
bool EnterIconDirectory( ResourceVisitor_t &visitor, const ResourceEntry_t &entry ) noexcept
{
	if ( visitor.m_eState == EVisitorState::Root )
	{
		if ( static_cast<i32>( entry.m_unName ) >= 0 &&
		     static_cast<u16>( entry.m_unName ) == reinterpret_cast<uptr>( RT_ICON ) )
		{
			visitor.m_eState = EVisitorState::TypeDirectory;
			return true;
		}
	}
	else if ( visitor.m_eState == EVisitorState::TypeDirectory )
	{
		if ( static_cast<i32>( entry.m_unName ) >= 0 && static_cast<u16>( entry.m_unName ) == visitor.m_unIconId )
		{
			visitor.m_eState = EVisitorState::NameDirectory;
			return true;
		}
	}
	return false;
}

// @note / sapdragon: only reachable through the vtable, so the export has no function here and no @orig can resolve
void HashIconData( ResourceVisitor_t &visitor, const u8 *pubData, u32 cubData ) noexcept
{
	ResetHash( visitor.m_Hash );
	UpdateHash( visitor.m_Hash, pubData, cubData );
	visitor.m_Hash.m_Md5.Final( visitor.m_Hash.m_rgubDigest );
	visitor.m_eState = EVisitorState::Done;
}

constexpr ResourceVisitorTable_t k_GroupIconVisitor{ EnterGroupIconDirectory, SelectLargestIcon,
                                                     LeaveResourceDirectory };
constexpr ResourceVisitorTable_t k_IconVisitor{ EnterIconDirectory, HashIconData, LeaveResourceDirectory };

// @orig: 81 EC ? ? ? ? 53 55 56 57 6A
bool HashLargestIcon( PeFile_t &file, u8 *pubDigest, u32 *pcubIcon ) noexcept
{
	memset( pubDigest, 0, crypto::hash::k_cubMd5Digest );
	if ( !IsPeFileOpen( file ) )
		return false;

	ResourceVisitor_t visitor;
	visitor.m_pTable = &k_GroupIconVisitor;
	visitor.m_eState = EVisitorState::Root;
	visitor.m_unIconId = 0;
	if ( !WalkResources( file, visitor ) || visitor.m_eState != EVisitorState::Done )
		return false;

	bool bHashed = false;
	visitor.m_pTable = &k_IconVisitor;
	visitor.m_eState = EVisitorState::Root;
	ResetHash( visitor.m_Hash );
	if ( WalkResources( file, visitor ) && visitor.m_eState == EVisitorState::Done )
	{
		memcpy( pubDigest, visitor.m_Hash.m_rgubDigest, sizeof( visitor.m_Hash.m_rgubDigest ) );
		bHashed = true;
		*pcubIcon = visitor.m_Hash.m_cubHashed;
	}
	ResetHash( visitor.m_Hash );
	return bHashed;
}

// @orig: 55 8B EC 83 EC ? 53 56 8B F1 33 DB 57 83 BE
void VerifySignature( PeFile_t &file ) noexcept
{
	file.m_unTrustStatus = 0;
	file.m_unTrustError = ERROR_INVALID_HANDLE;
	if ( !IsPeFileOpen( file ) )
		return;

	WINTRUST_FILE_INFO fileInfo{};
	fileInfo.cbStruct = sizeof( fileInfo );
	fileInfo.pcwszFilePath = L"";
	fileInfo.hFile = file.m_hFile;

	WINTRUST_DATA trustData{};
	trustData.cbStruct = sizeof( trustData );
	trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
	trustData.dwUnionChoice = WTD_CHOICE_FILE;
	trustData.dwStateAction = WTD_STATEACTION_VERIFY;
	trustData.pFile = &fileInfo;
	trustData.dwUIChoice = WTD_UI_NONE;

	GUID action = k_GuidVerifyV2;
	file.m_unTrustStatus = g_pImports->WinVerifyTrust( nullptr, &action, &trustData );
	file.m_unTrustError = g_pImports->GetLastError();

	trustData.dwStateAction = WTD_STATEACTION_CLOSE;
	g_pImports->WinVerifyTrust( nullptr, &action, &trustData );

	memset( &file.m_Signer, 0, sizeof( file.m_Signer ) );
	memset( &file.m_Issuer, 0, sizeof( file.m_Issuer ) );

	// @orig: inlined
	LARGE_INTEGER liSize{};
	g_pImports->GetFileSizeEx( file.m_hFile, &liSize );
	const HANDLE hMapping = g_pImports->CreateFileMappingW( file.m_hFile, nullptr, PAGE_READONLY, 0, 0, nullptr );
	const void *pView = hMapping ? g_pImports->MapViewOfFile( hMapping, FILE_MAP_READ, 0, 0, 0 ) : nullptr;
	if ( pView )
	{
		verify::CertContextSet_t set;
		static_cast<void>( verify::OpenCertificateContextFromBlob( g_pImports, &set, pView, liSize.LowPart,
		                                                           CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED ) );
		if ( set.m_hMsg )
			verify::ExtractCertChain( g_pImports, &set, &file.m_Signer, &file.m_Issuer );
		verify::ReleaseCertContext( g_pImports, &set );
		g_pImports->UnmapViewOfFile( pView );
	}
	if ( hMapping )
		g_pImports->CloseHandle( hMapping );
}

} // namespace

// @orig: 53 33 DB 56 8B F1
void InitPeFile( PeFile_t &file ) noexcept
{
	file.m_hFile = INVALID_HANDLE_VALUE;
	file.m_cubWindow = 0;
	file.m_ulWindowBase = 0;
	file.m_ibCursor = 0;
	file.m_ulRangeStart = 0;
	file.m_ulRangeEnd = 0;
	file.m_hProcess = nullptr;
	file.m_ulImageBase = 0;
	file.m_pSections = nullptr;
	file.m_pubRelocations = nullptr;
	file.m_cubRelocations = 0;
	file.m_ulRelocationDelta = 0;
	file.m_bPe64 = 0;
	file.m_cRelocationsApplied = 0;
	file.m_szPdbPath[0] = 0;
	file.m_bLayoutDigest = 0;
}

// @orig: 56 8B F1 8B 86
void ClosePeFile( PeFile_t &file ) noexcept
{
	if ( IsPeFileOpen( file ) )
	{
		g_pImports->CloseHandle( file.m_hFile );
		file.m_hFile = INVALID_HANDLE_VALUE;
	}
	file.m_cubWindow = 0;
	file.m_ulWindowBase = 0;
	file.m_ibCursor = 0;
	file.m_ulRangeStart = 0;
	file.m_ulRangeEnd = 0;
	file.m_hProcess = nullptr;
}

// @orig: 53 56 57 8B F1
void ResetPeFile( PeFile_t &file ) noexcept
{
	ClosePeFile( file );
	if ( file.m_pSections )
		util::HeapFree( file.m_pSections );
	if ( file.m_pubRelocations )
		util::HeapFree( file.m_pubRelocations );

	file.m_ulImageBase = 0;
	file.m_pSections = nullptr;
	file.m_pubRelocations = nullptr;
	file.m_cubRelocations = 0;
	file.m_ulRelocationDelta = 0;
	file.m_bPe64 = 0;
	file.m_cRelocationsApplied = 0;
}

// @orig: 56 8B F1 E8
EScanStatus OpenPeFile( PeFile_t &file, const wchar_t *pwszPath ) noexcept
{
	ResetPeFile( file );
	return OpenWithPrefixFallback( file, pwszPath ) ? EScanStatus::Ok : EScanStatus::OpenFailed;
}

// @orig: 51 53 55 56 8B F1 57 83 BE
EScanStatus ParsePeFile( PeFile_t &file ) noexcept
{
	if ( !IsPeFileOpen( file ) )
		return EScanStatus::NoFile;

	const EScanStatus eStatus = ParseHeaders( file );
	if ( eStatus != EScanStatus::Ok )
	{
		ResetPeFile( file );
		return eStatus;
	}

	u32 ibRawEnd = 0;
	for ( u32 iSection = 0; iSection < file.m_FileHeader.NumberOfSections; ++iSection )
	{
		const IMAGE_SECTION_HEADER &section = file.m_pSections[iSection];
		const u32 ibEnd = section.SizeOfRawData + section.PointerToRawData;
		if ( ibEnd > ibRawEnd )
			ibRawEnd = ibEnd;
	}

	const u32 cubFile = vac::file::GetFileSizeOrZero( g_pImports, file.m_hFile );
	const u32 cubAlignment =
	    file.m_bPe64 ? file.m_OptionalHeader64.SectionAlignment : file.m_OptionalHeader32.SectionAlignment;
	if ( ibRawEnd < cubFile )
	{
		++file.m_FileHeader.NumberOfSections;
		const u32 cubOverlay = cubFile - ibRawEnd;
		const u32 cSections = file.m_FileHeader.NumberOfSections;
		file.m_pSections = static_cast<IMAGE_SECTION_HEADER *>(
		    ReallocateHeap( file.m_pSections, sizeof( IMAGE_SECTION_HEADER ) * cSections ) );

		// @note / sapdragon: no section before it reads in front of the block, and a zero alignment divides by zero.
		// the original has both
		IMAGE_SECTION_HEADER &overlay = file.m_pSections[cSections - 1];
		const IMAGE_SECTION_HEADER &previous = file.m_pSections[static_cast<i32>( cSections ) - 2];
		u32 cubPrevious = previous.Misc.VirtualSize;
		if ( cubPrevious < previous.SizeOfRawData )
			cubPrevious = cubAlignment + previous.SizeOfRawData - 1 -
			              ( cubAlignment + previous.SizeOfRawData - 1 ) % cubAlignment;
		const u32 unNextRva = cubAlignment + cubPrevious + previous.VirtualAddress - 1;

		memset( &overlay, 0, sizeof( overlay ) );
		overlay.PointerToRawData = ibRawEnd;
		overlay.Characteristics = IMAGE_SCN_MEM_DISCARDABLE;
		overlay.SizeOfRawData = cubOverlay;
		overlay.VirtualAddress = unNextRva - unNextRva % cubAlignment;
		overlay.Misc.VirtualSize = cubAlignment + cubOverlay - 1 - ( cubAlignment + cubOverlay - 1 ) % cubAlignment;
		memcpy( overlay.Name, k_szOverlaySection, sizeof( k_szOverlaySection ) );
	}
	return EScanStatus::Ok;
}

// @orig: 55 8B EC 83 EC ? 56 57 33 FF
void BuildImageFingerprints( PeFile_t &file, ImageFingerprints_t &fingerprints ) noexcept
{
	HashContext_t hash;
	ResetHash( hash );
	if ( HashImage( file, hash, true ) )
		memcpy( fingerprints.m_rgubCodeDigest, hash.m_rgubDigest, sizeof( hash.m_rgubDigest ) );

	ResetHash( hash );
	if ( HashImage( file, hash, false ) )
		memcpy( fingerprints.m_rgubImageDigest, hash.m_rgubDigest, sizeof( hash.m_rgubDigest ) );

	fingerprints.m_unCheckSum = GetImageChecksum( file );
	fingerprints.m_unVlvSignature = 0;
	fingerprints.m_unTimeDateStamp = file.m_FileHeader.TimeDateStamp;
	if ( util::Read32( file.m_rgubDosStub ) == k_unVlvSignature )
		fingerprints.m_unVlvSignature = k_unVlvSignature;

	ResetHash( hash );
}

// @orig: 81 EC ? ? ? ? 53 55 56 57 8B F9
void BuildImageDetails( PeFile_t &file, ImageDetails_t &details ) noexcept
{
	details.m_cSections = static_cast<u8>( file.m_FileHeader.NumberOfSections );
	details.m_unTimeDateStamp = file.m_FileHeader.TimeDateStamp;
	details.m_unEntryPoint =
	    file.m_bPe64 ? file.m_OptionalHeader64.AddressOfEntryPoint : file.m_OptionalHeader32.AddressOfEntryPoint;
	details.m_unCheckSum = GetImageChecksum( file );

	HashContext_t hash;
	ResetHash( hash );
	file.m_bLayoutDigest = 1;
	if ( HashImage( file, hash, false ) )
	{
		details.m_LayoutDigestSize.m_cubHashed = hash.m_cubHashed;
		memcpy( details.m_rgubLayoutDigest, hash.m_rgubDigest, sizeof( hash.m_rgubDigest ) );
	}
	else
	{
		details.m_LayoutDigestSize.m_bFailed = 1;
	}
	file.m_bLayoutDigest = 0;

	ResetHash( hash );
	if ( HashImage( file, hash, false ) )
	{
		details.m_ImageDigestSize.m_cubHashed = hash.m_cubHashed;
		memcpy( details.m_rgubImageDigest, hash.m_rgubDigest, sizeof( hash.m_rgubDigest ) );
	}
	else
	{
		details.m_ImageDigestSize.m_bFailed = 1;
	}
	ResetHash( hash );

	u32 cReported = file.m_FileHeader.NumberOfSections;
	if ( cReported > ARRAYSIZE( details.m_rgSections ) )
		cReported = ARRAYSIZE( details.m_rgSections );

	for ( u32 iSection = 0; iSection < cReported; ++iSection )
	{
		const IMAGE_SECTION_HEADER &section = file.m_pSections[iSection];

		ResetHash( hash );
		if ( HashSection( file, section, hash ) )
		{
			hash.m_Md5.Final( hash.m_rgubDigest );
			details.m_rgSectionDigestSizes[iSection].m_cubHashed = hash.m_cubHashed;
			memcpy( details.m_rgrgubSectionDigests[iSection], hash.m_rgubDigest, sizeof( hash.m_rgubDigest ) );
		}
		else
		{
			details.m_rgSectionDigestSizes[iSection].m_bFailed = 1;
		}

		SectionRow_t &row = details.m_rgSections[iSection];
		memcpy( row.m_rgubName, section.Name, IMAGE_SIZEOF_SHORT_NAME );
		row.m_unCharacteristics = section.Characteristics;
		row.m_cubRawData = section.SizeOfRawData;
		row.m_unZero = 0;
		row.m_unVirtualAddress = section.VirtualAddress;
	}

	u32 cubIcon = 0;
	if ( HashLargestIcon( file, details.m_rgubIconDigest, &cubIcon ) )
		details.m_IconDigestSize.m_cubHashed = cubIcon;
	else
		details.m_IconDigestSize.m_bFailed = 1;

	details.m_cReportedSections = static_cast<u8>( cReported + 4 );

	if ( ParseDebugDirectory( file ) == EScanStatus::Ok )
		util::CopyA( details.m_szPdbPath, file.m_szPdbPath, sizeof( details.m_szPdbPath ) );

	ResetHash( hash );
}

// @orig: 51 56 57 68
void ExportImageHeaders( PeFile_t &file, ImageHeaders_t &headers ) noexcept
{
	memset( &headers, 0, sizeof( headers ) );
	memcpy( &headers.m_FileHeader, &file.m_OriginalFileHeader, sizeof( headers.m_FileHeader ) );
	memcpy( headers.m_rgubOptionalHeader,
	        file.m_bPe64 ? static_cast<const void *>( &file.m_OptionalHeader64 )
	                     : static_cast<const void *>( &file.m_OptionalHeader32 ),
	        sizeof( headers.m_rgubOptionalHeader ) );
	memcpy( headers.m_rgubDosStub, file.m_rgubDosStub, sizeof( headers.m_rgubDosStub ) );

	const IMAGE_SECTION_HEADER *pOverlay = FindOverlaySection( file );
	if ( pOverlay )
	{
		const u32 ibOverlay = IsPeFileOpen( file ) ? pOverlay->PointerToRawData : pOverlay->VirtualAddress;
		if ( SeekPeFile( file, ibOverlay ) )
		{
			const u8 *pubOverlay = ReadWindow( file, sizeof( headers.m_rgubOverlayStart ) );
			if ( pubOverlay )
				memcpy( headers.m_rgubOverlayStart, pubOverlay, sizeof( headers.m_rgubOverlayStart ) );
		}
	}

	VerifySignature( file );
	headers.m_unTrustStatus = file.m_unTrustStatus;
	headers.m_unTrustError = file.m_unTrustError;
	memcpy( &headers.m_Issuer, &file.m_Issuer, sizeof( headers.m_Issuer ) );
	memcpy( &headers.m_Signer, &file.m_Signer, sizeof( headers.m_Signer ) );
}

} // namespace vac::workers::process_file_identity
