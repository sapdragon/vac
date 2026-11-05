// @binary: 33211402
#include "../scanner.hpp"
#include "crt/intrinsics.hpp"
#include "pe/pe.hpp"

namespace vac::workers::image_scan
{

namespace
{

enum class EFilterState : u32
{
	Root = 0,
	InType = 1,
	InName = 2,
	Done = 3,
};

struct ResourceFilter_t;

// @note / sapdragon: the original is two small classes with a vtable, this is that table
struct ResourceFilterTable_t
{
	bool ( *m_pfnEnterDirectory )( ResourceFilter_t *pFilter, const IMAGE_RESOURCE_DIRECTORY_ENTRY *pEntry ) noexcept;
	void ( *m_pfnVisitData )( ResourceFilter_t *pFilter, const IMAGE_RESOURCE_DIRECTORY_ENTRY *pEntry,
	                          const u8 *pubData, u32 cubData ) noexcept;
	void ( *m_pfnLeaveDirectory )( ResourceFilter_t *pFilter ) noexcept;
};

#pragma pack( push, 1 )
struct GroupIconHeader_t
{
	u16 m_unReserved;
	u16 m_unType;
	u16 m_cEntries;
};

struct GroupIconEntry_t
{
	u8 m_cWidth;
	u8 m_cHeight;
	u8 m_cColors;
	u8 m_unReserved;
	u16 m_cPlanes;
	u16 m_cBitsPerPixel;
	u32 m_cubImage;
	u16 m_unId;
};

struct IconDirectory_t
{
	u8 m_rgubHeader[4];
	u16 m_cImages;
	u8 m_rgubEntry[12];
	u32 m_ibImage;
};

struct ResourceFilter_t
{
	const ResourceFilterTable_t *m_pTable;
	EFilterState m_eState;
	u32 m_unIconId;
	IconDirectory_t m_IconDirectory;
};

struct IconHashFilter_t
{
	ResourceFilter_t m_Filter;
	u8 m_rgubUnused[2];
	HybridHash_t m_Hash;
};
#pragma pack( pop )
VAC_LAYOUT_SIZE( GroupIconHeader_t, 6 );
VAC_LAYOUT( GroupIconEntry_t, m_unId, 12 );
VAC_LAYOUT_SIZE( GroupIconEntry_t, 14 );
VAC_LAYOUT_SIZE( IconDirectory_t, 22 );
VAC_LAYOUT( ResourceFilter_t, m_IconDirectory, 12 );
VAC_LAYOUT( IconHashFilter_t, m_Hash, 36 );

bool IsEntryId( const IMAGE_RESOURCE_DIRECTORY_ENTRY *pEntry, u32 unId ) noexcept
{
	return static_cast<i32>( pEntry->Name ) >= 0 && static_cast<u16>( pEntry->Name ) == unId;
}

// @orig: 83 79 ? ? 75 ? 8B 44 24 ? 83 38 ? 7C ? 66 83 38 ? 75 ? C7 41 ? ? ? ? ? B0 ? EB ? 83 79 ? ? 75 ? C7 41
bool GroupIconEnterDirectory( ResourceFilter_t *pFilter, const IMAGE_RESOURCE_DIRECTORY_ENTRY *pEntry ) noexcept
{
	if ( pFilter->m_eState != EFilterState::Root )
	{
		if ( pFilter->m_eState == EFilterState::InType )
		{
			pFilter->m_eState = EFilterState::InName;
			return true;
		}
	}
	else if ( IsEntryId( pEntry, LOWORD( RT_GROUP_ICON ) ) )
	{
		pFilter->m_eState = EFilterState::InType;
		return true;
	}
	return false;
}

// @orig: 51 53 8B D9 89 5C 24
void GroupIconVisitData( ResourceFilter_t *pFilter, const IMAGE_RESOURCE_DIRECTORY_ENTRY *, const u8 *pubData,
                         u32 cubData ) noexcept
{
	if ( pFilter->m_eState == EFilterState::Done || !pubData || cubData < sizeof( GroupIconHeader_t ) )
		return;

	const u32 cEntries = reinterpret_cast<const GroupIconHeader_t *>( pubData )->m_cEntries;
	if ( static_cast<u16>( cubData ) < sizeof( GroupIconEntry_t ) * cEntries + sizeof( GroupIconHeader_t ) ||
	     !cEntries )
		return;

	u32 unLargestArea = 0;
	const u8 *pubBest = nullptr;
	const u8 *pubEntry = pubData + sizeof( GroupIconHeader_t );
	for ( u32 iEntry = 0; iEntry < cEntries; ++iEntry, pubEntry += sizeof( GroupIconEntry_t ) )
	{
		const u32 unArea = pubEntry[0] * pubEntry[1];
		if ( unArea > unLargestArea )
		{
			unLargestArea = unArea;
			pubBest = pubEntry;
		}
	}
	if ( !pubBest )
		return;

	pFilter->m_unIconId = reinterpret_cast<const GroupIconEntry_t *>( pubBest )->m_unId;
	pFilter->m_eState = EFilterState::Done;
	memcpy( pFilter->m_IconDirectory.m_rgubHeader, pubData, sizeof( pFilter->m_IconDirectory.m_rgubHeader ) );
	pFilter->m_IconDirectory.m_cImages = 1;
	memcpy( pFilter->m_IconDirectory.m_rgubEntry, pubBest, sizeof( pFilter->m_IconDirectory.m_rgubEntry ) );
	pFilter->m_IconDirectory.m_ibImage = sizeof( IconDirectory_t );
}

// @orig: 8B 41 ? 83 E8
void LeaveDirectory( ResourceFilter_t *pFilter ) noexcept
{
	if ( pFilter->m_eState == EFilterState::Root || pFilter->m_eState == EFilterState::InType )
		pFilter->m_eState = EFilterState::Root;
	else if ( pFilter->m_eState == EFilterState::InName )
		pFilter->m_eState = EFilterState::InType;
}

// @orig: 83 79 ? ? 75 ? 8B 44 24 ? 83 38 ? 7C ? 66 83 38 ? 75 ? C7 41 ? ? ? ? ? B0 ? EB ? 83 79 ? ? 75 ? 8B 44 24
bool IconEnterDirectory( ResourceFilter_t *pFilter, const IMAGE_RESOURCE_DIRECTORY_ENTRY *pEntry ) noexcept
{
	if ( pFilter->m_eState != EFilterState::Root )
	{
		if ( pFilter->m_eState == EFilterState::InType && IsEntryId( pEntry, pFilter->m_unIconId ) )
		{
			pFilter->m_eState = EFilterState::InName;
			return true;
		}
	}
	else if ( IsEntryId( pEntry, LOWORD( RT_ICON ) ) )
	{
		pFilter->m_eState = EFilterState::InType;
		return true;
	}
	return false;
}

// @orig: 56 57 8B F9 8D 77
void IconVisitData( ResourceFilter_t *pFilter, const IMAGE_RESOURCE_DIRECTORY_ENTRY *, const u8 *pubData,
                    u32 cubData ) noexcept
{
	HybridHash_t *pHash = &reinterpret_cast<IconHashFilter_t *>( pFilter )->m_Hash;
	ResetHybridHash( pHash );
	UpdateHybridHash( pHash, pubData, cubData );
	if ( HasFlag( pHash->m_eMode, EHashMode::Md5 ) )
		pHash->m_Md5.Final( pHash->m_rgubDigest );
	pFilter->m_eState = EFilterState::Done;
}

constexpr ResourceFilterTable_t k_GroupIconFilterTable{ GroupIconEnterDirectory, GroupIconVisitData, LeaveDirectory };
constexpr ResourceFilterTable_t k_IconFilterTable{ IconEnterDirectory, IconVisitData, LeaveDirectory };

// @orig: 83 EC ? 53 8B 5C 24 ? 55 56 57 8B 7C 24
bool ReadResourceDataEntry( ScannerContext_t *pCtx, u32 ibEntry, u8 **ppubData, u32 *pcubData ) noexcept
{
	*pcubData = 0;
	*ppubData = nullptr;
	if ( !ReaderSeek( pCtx, ibEntry, false ) )
		return false;

	const u8 *pubWindow = ReaderWindow( pCtx, sizeof( IMAGE_RESOURCE_DATA_ENTRY ) );
	if ( !pubWindow )
		return false;

	IMAGE_RESOURCE_DATA_ENTRY entry;
	memcpy( &entry, pubWindow, sizeof( entry ) );
	if ( !entry.Size )
		return false;

	const u32 ibData =
	    pe::RvaToFileOffset( pCtx->m_pSections, pCtx->m_FileHeader.NumberOfSections, entry.OffsetToData );
	if ( ibData == pe::k_unInvalidOffset || !ReaderSeek( pCtx, ibData, false ) )
		return false;

	*pcubData = entry.Size;
	*ppubData = static_cast<u8 *>( AllocBytes( entry.Size ) );
	if ( !ReaderReadBytes( pCtx, *ppubData, entry.Size ) )
	{
		FreeBytes( *ppubData );
		*ppubData = nullptr;
		*pcubData = 0;
		return false;
	}
	return true;
}

// @orig: 51 51 53 55 56 57 6A
bool WalkResourceDirectory( ScannerContext_t *pCtx, ResourceFilter_t *pFilter, u32 ibRoot, u32 ibDirectory ) noexcept
{
	if ( !ReaderSeek( pCtx, ibDirectory, false ) )
		return false;

	const auto *pWindow =
	    reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY *>( ReaderWindow( pCtx, sizeof( IMAGE_RESOURCE_DIRECTORY ) ) );
	if ( !pWindow )
		return false;

	const u32 cubEntries =
	    ( pWindow->NumberOfIdEntries + pWindow->NumberOfNamedEntries ) * sizeof( IMAGE_RESOURCE_DIRECTORY_ENTRY );
	if ( !ReaderSeek( pCtx, ibDirectory, false ) )
		return false;

	const u8 *pubWindow = ReaderWindow( pCtx, cubEntries + sizeof( IMAGE_RESOURCE_DIRECTORY ) );
	if ( !pubWindow )
		return false;

	auto *pDirectory = static_cast<IMAGE_RESOURCE_DIRECTORY *>( AllocBytes( sizeof( IMAGE_RESOURCE_DIRECTORY ) ) );
	memcpy( pDirectory, pubWindow, sizeof( IMAGE_RESOURCE_DIRECTORY ) );

	auto *pEntries = static_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY *>( AllocBytes( cubEntries ) );
	memcpy( pEntries, pubWindow + sizeof( IMAGE_RESOURCE_DIRECTORY ), cubEntries );

	for ( i32 iEntry = 0; iEntry < pDirectory->NumberOfNamedEntries + pDirectory->NumberOfIdEntries; ++iEntry )
	{
		const IMAGE_RESOURCE_DIRECTORY_ENTRY *pEntry = &pEntries[iEntry];
		if ( static_cast<i32>( pEntry->OffsetToData ) < 0 )
		{
			if ( pFilter->m_pTable->m_pfnEnterDirectory( pFilter, pEntry ) )
			{
				WalkResourceDirectory( pCtx, pFilter, ibRoot, ibRoot + ( pEntry->OffsetToData & 0x7FFFFFFF ) );
				pFilter->m_pTable->m_pfnLeaveDirectory( pFilter );
			}
		}
		else
		{
			u8 *pubData = nullptr;
			u32 cubData = 0;
			if ( ReadResourceDataEntry( pCtx, ibRoot + pEntry->OffsetToData, &pubData, &cubData ) )
			{
				pFilter->m_pTable->m_pfnVisitData( pFilter, pEntry, pubData, cubData );
				FreeBytes( pubData );
			}
		}
	}

	FreeBytes( pDirectory );
	FreeBytes( pEntries );
	return true;
}

// @orig: 51 56 8B F1 B8
bool WalkResourceDirectoryRoot( ScannerContext_t *pCtx, ResourceFilter_t *pFilter ) noexcept
{
	const IMAGE_DATA_DIRECTORY &directory =
	    pCtx->m_bPe64 ? pCtx->m_OptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]
	                  : pCtx->m_OptionalHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	if ( !directory.Size )
		return false;

	const u32 ibRoot =
	    pe::RvaToFileOffset( pCtx->m_pSections, pCtx->m_FileHeader.NumberOfSections, directory.VirtualAddress );
	if ( ibRoot == pe::k_unInvalidOffset )
		return false;
	return WalkResourceDirectory( pCtx, pFilter, ibRoot, ibRoot );
}

} // namespace

// @orig: 81 EC ? ? ? ? 53 55 56 57 6A
bool HashBestIconResource( ScannerContext_t *pCtx, u8 *pubDigest, u32 *pcubIcon ) noexcept
{
	bool bResult = false;
	memset( pubDigest, 0, 16 );
	if ( pCtx->m_hFile == INVALID_HANDLE_VALUE )
		return false;

	ResourceFilter_t groupFilter;
	groupFilter.m_pTable = &k_GroupIconFilterTable;
	groupFilter.m_eState = EFilterState::Root;
	groupFilter.m_unIconId = 0;
	if ( !WalkResourceDirectoryRoot( pCtx, &groupFilter ) || groupFilter.m_eState != EFilterState::Done )
		return false;

	IconHashFilter_t iconFilter;
	iconFilter.m_Filter.m_pTable = &k_IconFilterTable;
	iconFilter.m_Filter.m_eState = EFilterState::Root;
	iconFilter.m_Filter.m_unIconId = groupFilter.m_unIconId;
	iconFilter.m_Filter.m_IconDirectory = groupFilter.m_IconDirectory;
	ConstructHybridHash( &iconFilter.m_Hash );

	if ( WalkResourceDirectoryRoot( pCtx, &iconFilter.m_Filter ) &&
	     iconFilter.m_Filter.m_eState == EFilterState::Done &&
	     GetHybridHashResult( &iconFilter.m_Hash, pubDigest ) == 16 )
	{
		bResult = true;
		*pcubIcon = iconFilter.m_Hash.m_cubTotal;
	}

	ResetHybridHash( &iconFilter.m_Hash );
	return bResult;
}

} // namespace vac::workers::image_scan
