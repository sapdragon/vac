// @binary: a07ed54b
#pragma once

#include "bootstrap/imports.hpp"
#include "core/layout.hpp"
#include "core/scan_status.hpp"

namespace vac::workers::system_info
{

inline constexpr u32 k_cubReaderPage = 4096;

// @note / sapdragon: valve's reader also works on memory and other processes, this module only hands it a file
#pragma pack( push, 1 )
class CPeFileReader
{
public:
	CPeFileReader() noexcept;

	// @orig: 83 B9
	[[nodiscard]] bool IsOpen() const noexcept { return m_hFile != INVALID_HANDLE_VALUE; }

	void Close() noexcept;
	void Release() noexcept;
	[[nodiscard]] EScanStatus Open( HANDLE hFile ) noexcept;

	[[nodiscard]] bool Seek( u32 ibOffset, bool bForce ) noexcept;
	[[nodiscard]] const u8 *Read( u32 cubRead ) noexcept;
	[[nodiscard]] bool ReadBytes( void *pDst, u32 cubRead ) noexcept;
	[[nodiscard]] i32 ReadString( char *pszDst, u32 cchDst ) noexcept;

	[[nodiscard]] EScanStatus ParseExports() noexcept;

	char m_szPath[260];
	u8 m_rgubWindow[2 * k_cubReaderPage];
	u8 m_rgubUnused2104[4];
	u64 m_ulWindowBase;
	u32 m_ibCursor;
	u32 m_cubWindow;
	u64 m_ulRangeStart;
	u64 m_ulRangeEnd;
	HANDLE m_hFile;
	HANDLE m_hProcess;
	u64 m_ulMemoryBase;
	u64 m_ulImageBase;
	u32 m_rgunUnused2140[3];
	u8 m_unUnused214C;
	u8 m_bPe64;
	IMAGE_DOS_HEADER m_DosHeader;
	u8 m_rgubUnused218E[2];
	u8 m_rgubDosStub[144];
	IMAGE_FILE_HEADER m_RawFileHeader;
	IMAGE_FILE_HEADER m_FileHeader;
	IMAGE_OPTIONAL_HEADER32 m_OptionalHeader32;
	IMAGE_OPTIONAL_HEADER64 m_OptionalHeader64;
	IMAGE_SECTION_HEADER *m_pSections;
	void **m_ppSectionData;
	u8 m_rgubUnused2420[84];
	u8 m_unUnused2474;
	u8 m_rgubUnused2475[259];
	u32 m_unUnused2578;
	u32 m_unUnused257C;
	char m_szExportName[260];
	i32 m_cExportNames;
	char **m_ppszExportNames;
	u32 *m_punExportFunctions;
	void *m_pUnused2690;
	u32 m_unUnused2694;
	i32 m_cForwarderLibraries;
	char *m_rgpszForwarderLibraries[32];
	u8 m_rgubUnused271C[16];
	u8 m_unUnused272C;
	u8 m_rgubUnused272D[403];

private:
	void SetMemoryRangeEnd( u32 ulRangeEnd ) noexcept;
	[[nodiscard]] bool AttachFile( HANDLE hFile ) noexcept;
	[[nodiscard]] EScanStatus ParseHeaders() noexcept;
	[[nodiscard]] EScanStatus Load() noexcept;
};
#pragma pack( pop )
VAC_LAYOUT( CPeFileReader, m_rgubWindow, 260 );
VAC_LAYOUT( CPeFileReader, m_ulWindowBase, 8456 );
VAC_LAYOUT( CPeFileReader, m_ibCursor, 8464 );
VAC_LAYOUT( CPeFileReader, m_cubWindow, 8468 );
VAC_LAYOUT( CPeFileReader, m_ulRangeStart, 8472 );
VAC_LAYOUT( CPeFileReader, m_ulRangeEnd, 8480 );
VAC_LAYOUT( CPeFileReader, m_hFile, 8488 );
VAC_LAYOUT( CPeFileReader, m_hProcess, 8492 );
VAC_LAYOUT( CPeFileReader, m_ulMemoryBase, 8496 );
VAC_LAYOUT( CPeFileReader, m_ulImageBase, 8504 );
VAC_LAYOUT( CPeFileReader, m_bPe64, 8525 );
VAC_LAYOUT( CPeFileReader, m_DosHeader, 8526 );
VAC_LAYOUT( CPeFileReader, m_rgubDosStub, 8592 );
VAC_LAYOUT( CPeFileReader, m_RawFileHeader, 8736 );
VAC_LAYOUT( CPeFileReader, m_FileHeader, 8756 );
VAC_LAYOUT( CPeFileReader, m_OptionalHeader32, 8776 );
VAC_LAYOUT( CPeFileReader, m_OptionalHeader64, 9000 );
VAC_LAYOUT( CPeFileReader, m_pSections, 9240 );
VAC_LAYOUT( CPeFileReader, m_ppSectionData, 9244 );
VAC_LAYOUT( CPeFileReader, m_unUnused2474, 9332 );
VAC_LAYOUT( CPeFileReader, m_unUnused2578, 9592 );
VAC_LAYOUT( CPeFileReader, m_szExportName, 9600 );
VAC_LAYOUT( CPeFileReader, m_cExportNames, 9860 );
VAC_LAYOUT( CPeFileReader, m_ppszExportNames, 9864 );
VAC_LAYOUT( CPeFileReader, m_punExportFunctions, 9868 );
VAC_LAYOUT( CPeFileReader, m_pUnused2690, 9872 );
VAC_LAYOUT( CPeFileReader, m_cForwarderLibraries, 9880 );
VAC_LAYOUT( CPeFileReader, m_rgpszForwarderLibraries, 9884 );
VAC_LAYOUT( CPeFileReader, m_unUnused272C, 10028 );
VAC_LAYOUT_SIZE( CPeFileReader, 10432 );

} // namespace vac::workers::system_info
