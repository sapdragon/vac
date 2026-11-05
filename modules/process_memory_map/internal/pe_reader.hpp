#pragma once

#include "crypto/hash/md5.hpp"
#include "internal/types.hpp"

namespace vac::workers::process_memory_map
{

class CPeReader
{
public:
	explicit CPeReader( const SystemImports_t *pImports ) noexcept;

	void CloseSource() noexcept;
	void Release() noexcept;

	[[nodiscard]] bool AttachFile( HANDLE hFile ) noexcept;
	[[nodiscard]] EScanStatus ParseFile() noexcept;
	[[nodiscard]] EScanStatus ParseProcessImage( u64 ulBase, HANDLE hProcess ) noexcept;

	[[nodiscard]] const IMAGE_SECTION_HEADER *FindSectionByName( const char *pszName ) const noexcept;

	[[nodiscard]] bool HashImage( u8 *pubDigest ) noexcept;

	[[nodiscard]] bool IsPe64() const noexcept { return m_bPe64; }
	[[nodiscard]] bool HasValveStub() const noexcept;
	[[nodiscard]] u32 GetSizeOfImage() const noexcept;

private:
	[[nodiscard]] bool IsFile() const noexcept;
	[[nodiscard]] u8 *ReadChunk( u32 cub ) noexcept;
	[[nodiscard]] bool Read( void *pOutput, u32 cub ) noexcept;
	[[nodiscard]] bool Seek( u32 ibOffset ) noexcept;
	[[nodiscard]] EScanStatus ParseHeaders() noexcept;
	void AttachProcess( u64 ulBase, HANDLE hProcess ) noexcept;
	[[nodiscard]] bool LoadRelocations() noexcept;
	[[nodiscard]] bool IsRelocated() const noexcept;
	[[nodiscard]] bool ApplyRelocations( u8 *pubChunk, u32 unChunkRva, u32 cubChunk ) noexcept;
	void HashRangeAroundDirectories( const u8 *pubChunk, u32 unChunkRva, u32 cubChunk,
	                                 crypto::hash::Md5_t &md5 ) const noexcept;
	[[nodiscard]] u64 GetImageBase() const noexcept;
	[[nodiscard]] bool BeginSection( const IMAGE_SECTION_HEADER &section ) noexcept;
	[[nodiscard]] bool HashNextChunk( crypto::hash::Md5_t &md5 ) noexcept;
	[[nodiscard]] bool HashSection( const IMAGE_SECTION_HEADER &section, crypto::hash::Md5_t &md5 ) noexcept;

	static constexpr u32 k_cubPage = 0x1000;

	const SystemImports_t *m_pImports;

	u8 m_rgubWindow[2 * k_cubPage];
	// @note / sapdragon: a relocated dword can start in the last bytes of the window and run up to 3 past it. valve
	// has padding here too, it stops the patch from landing in m_ulWindowOffset
	u8 m_rgubWindowSlack[4];
	u64 m_ulWindowOffset;
	u32 m_ibCursor;
	u32 m_cubValid;

	HANDLE m_hFile;
	HANDLE m_hProcess;
	u64 m_ulRemoteBase;
	u64 m_ulRelocationDelta;
	bool m_bPe64;

	IMAGE_DOS_HEADER m_DosHeader;
	u8 m_rgubDosStub[144];
	IMAGE_FILE_HEADER m_FileHeader;
	// @note / sapdragon: same as m_FileHeader except that its section count includes .extra
	IMAGE_FILE_HEADER m_FileHeaderWithOverlay;
	IMAGE_OPTIONAL_HEADER32 m_Optional32;
	IMAGE_OPTIONAL_HEADER64 m_Optional64;
	IMAGE_SECTION_HEADER *m_pSections;

	u8 *m_pubRelocations;
	u32 m_cubRelocations;

	u32 m_cubSectionLeft;
	u32 m_unSectionRva;
	u32 m_ibRelocationCursor;
};

} // namespace vac::workers::process_memory_map
