#pragma once

#include "bootstrap/imports.hpp"
#include "core/scan_status.hpp"
#include "core/types.hpp"
#include "crypto/hash/md5.hpp"

namespace vac::workers::driver_inventory
{

// @note / sapdragon: valve's reader also has a process memory mode, nothing here reaches it, so only files
class CPeFile
{
public:
	void Init( const SystemImports_t *pImports ) noexcept;
	EScanStatus Open( u32 unVolumeSerial, u64 ulFileId, u32 *punLastError ) noexcept;
	EScanStatus ParseAndAppendOverlay() noexcept;
	[[nodiscard]] bool HashHeadersAndSelectedSection( crypto::hash::Md5_t &md5, u8 *pubDigest ) noexcept;
	void Reset() noexcept;
	void Close() noexcept;

private:
	bool Attach( HANDLE hFile ) noexcept;
	u8 *ReadWindow( u32 cubWanted ) noexcept;
	bool Read( void *pOut, i32 cubWanted ) noexcept;
	bool Seek( u32 ibFile ) noexcept;
	EScanStatus ParseHeaders() noexcept;
	bool LoadRelocations() noexcept;
	bool IsRelocated() const noexcept;
	bool ApplyRelocations( u8 *pubChunk, u32 unChunkRva, u32 cubChunk, i32 *pibCursor ) noexcept;
	void HashRange( const u8 *pubChunk, u32 unRva, u32 cubChunk, crypto::hash::Md5_t &md5 ) noexcept;
	u64 GetImageBase() const noexcept;
	bool BeginSectionStream( const IMAGE_SECTION_HEADER &section ) noexcept;
	bool HashNextSectionChunk( crypto::hash::Md5_t &md5 ) noexcept;
	bool HashSectionStream( const IMAGE_SECTION_HEADER &section, crypto::hash::Md5_t &md5 ) noexcept;
	void SlideWindow() noexcept;

	// @note / sapdragon: first on purpose, see ImageFrame_t. nothing reads it, but a path overrun runs into it
	char m_szName[260];
	u8 m_rgubWindow[0x2000];
	const SystemImports_t *m_pImports;
	u64 m_ulWindowBase;
	u32 m_ibCursor;
	u32 m_cubValid;
	HANDLE m_hFile;
	u64 m_ulRelocationDelta;
	bool m_bPe64;
	IMAGE_DOS_HEADER m_DosHeader;
	u8 m_rgubDosStub[144];
	IMAGE_FILE_HEADER m_RawFileHeader;
	IMAGE_FILE_HEADER m_FileHeader;
	IMAGE_OPTIONAL_HEADER32 m_Optional32;
	IMAGE_OPTIONAL_HEADER64 m_Optional64;
	IMAGE_SECTION_HEADER *m_pSections;
	u8 *m_pubRelocations;
	i32 m_cubRelocations;
	i32 m_cubSectionLeft;
	u32 m_unSectionRva;
	i32 m_ibRelocationCursor;
};

} // namespace vac::workers::driver_inventory
