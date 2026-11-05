#pragma once

#include "bootstrap/imports.hpp"
#include "core/types.hpp"
#include "crypto/hash/md5.hpp"

namespace vac::pe
{

inline constexpr u32 k_unInvalidOffset = 0xFFFFFFFFu;
inline constexpr u32 k_unRelocationBase = 0x10000000u;
inline constexpr u32 k_cMaxSections = 0x40;

struct RangePair_t
{
	u32 m_rgunStart[2];
	u32 m_rgunEnd[2];
};

struct NormalizedHashParams_t
{
	u32 m_unLoadedBase32;

	// @note / sapdragon: driver_inventory adds .extra, process_memory_map does not
	bool m_bAppendOverlaySection;
};

[[nodiscard]] const IMAGE_DATA_DIRECTORY *GetDataDirectory( const void *pOptionalHeader, bool bPe64,
                                                            u32 iDirectory ) noexcept;

[[nodiscard]] const IMAGE_SECTION_HEADER *FindSectionByRva( const IMAGE_SECTION_HEADER *pSections, u32 cSections,
                                                            u32 unRva ) noexcept;

[[nodiscard]] u32 RvaToFileOffset( const IMAGE_SECTION_HEADER *pSections, u32 cSections, u32 unRva ) noexcept;

[[nodiscard]] bool RvaToFileOffsetLargestSpan( const IMAGE_SECTION_HEADER *pSections, u32 cSections, u32 unRva,
                                               u32 *pibFileOffset ) noexcept;

void SplitAroundDirectory( u32 unDirectoryVa, u32 cubDirectory, u32 unStart, u32 unEnd, RangePair_t &ranges ) noexcept;

[[nodiscard]] bool ApplyRelocationsForHash( const u8 *pubFile, u32 cubFile, const IMAGE_SECTION_HEADER *pSections,
                                            u32 cSections, const IMAGE_DATA_DIRECTORY &relocations, u32 unImageBase,
                                            u32 unChunkRva, u8 *pubChunk, u32 cubChunk ) noexcept;

[[nodiscard]] bool HashSection( const u8 *pubFile, u32 cubFile, const IMAGE_SECTION_HEADER &section,
                                const IMAGE_SECTION_HEADER *pSections, u32 cSections, const void *pOptionalHeader,
                                bool bPe64, u32 unImageBase32, crypto::hash::Md5_t &md5 ) noexcept;

[[nodiscard]] const IMAGE_SECTION_HEADER *SelectHashSection( const IMAGE_SECTION_HEADER *pSections,
                                                             u32 cSections ) noexcept;

[[nodiscard]] bool AppendOverlaySection( IMAGE_SECTION_HEADER *pSections, u32 *pcSections, u32 cubFile,
                                         u32 unSectionAlignment ) noexcept;

[[nodiscard]] bool HashNormalizedPeImage( const u8 *pubFile, u32 cubFile, u8 *pubDigest,
                                          const NormalizedHashParams_t &params ) noexcept;

} // namespace vac::pe
