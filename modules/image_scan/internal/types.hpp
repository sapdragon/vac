#pragma once

#include "bootstrap/imports.hpp"
#include "core/layout.hpp"
#include "core/packets.hpp"
#include "core/scan_status.hpp"
#include "nt/nt.hpp"
#include "process/capture_flags.hpp"
#include "verify/cert_chain.hpp"

namespace vac::workers::image_scan
{

inline constexpr u32 k_unFailedFlag = 0x80000000u;
inline constexpr u32 k_unByteCountMask = 0x7FFFFFFFu;

#pragma pack( push, 1 )

// @note / sapdragon: file id and volume serial when m_unPid and m_unFlags are zero, otherwise an address
struct Input_t
{
	u8 m_rgubBootstrap[32];
	u8 m_unFlags;
	u8 m_rgubUnused0[63];
	u32 m_unPid;
	u64 m_ulTarget;
	u32 m_unVolumeSerial;
	u8 m_rgubUnused1[48];
};

struct SectionRecord_t
{
	u32 m_cubRaw;
	u32 m_unVirtualAddress;
	u32 m_unCharacteristics;
	u32 m_unReserved;
	char m_rgchName[8];
};

// @note / sapdragon: top bit on a byte count means that hash failed
struct ModuleReport_t
{
	EScanStatus m_eStatus;
	u32 m_unFirstProtect;
	u32 m_cubContiguous;
	u32 m_unProtectMask;
	u32 m_cubImage;
	u32 m_unTimeDateStamp;
	u32 m_unCheckSum;
	u32 m_unEntryPoint;
	u8 m_cSections;
	u8 m_cRegions;
	u8 m_bListedInProcess;
	u8 m_cReportedHashes;
	u32 m_cubStream;
	u32 m_cubLoadedImage;
	u32 m_cubImageHash;
	u32 m_cubIcon;
	u32 m_rgcubSections[12];
	u8 m_rgubStreamMd5[16];
	u8 m_rgubLoadedImageMd5[16];
	u8 m_rgubImageMd5[16];
	u8 m_rgubIconMd5[16];
	u8 m_rgubSectionMd5[12][16];
	SectionRecord_t m_rgSections[12];
	char m_szPdbPath[260];
	u8 m_rgubUnused[124];
};

struct PeHeadersReport_t
{
	IMAGE_FILE_HEADER m_FileHeader;
	u8 m_rgubOptionalHeader[0xE0];
	u8 m_rgubUnused0[16];
	u8 m_bCatalogValid;
	u8 m_bVerified;
	u8 m_rgubUnused1[2];
	u8 m_rgubOverlayHead[8];
	u8 m_rgubDosStub[16];
	u32 m_unWinTrustStatus;
	u32 m_unWinTrustLastError;
	union
	{
		char m_szCatalogPath[120];
		struct
		{
			verify::CertIdentity_t m_Signer;
			verify::CertIdentity_t m_Issuer;
		};
	};
};

struct PatternReport_t
{
	u32 m_rgunPatternBits[8];
	u32 m_cubText;
	u32 m_unReserved;
	char m_szText[1200];
};

struct Report_t
{
	u8 m_rgubDispatcher[16];
	EScanStatus m_eStatus;
	u32 m_unPid;
	u64 m_ulCreationTime;
	ModuleReport_t m_Primary;
	ModuleReport_t m_Secondary;
	char m_szMappedPath[256];
	u32 m_unVolumeSerial;
	u64 m_ulFileIndex;
	u32 m_bFsRedirectionDisabled;
	u32 m_unReportVersion;
	u32 m_unLastError;
	PatternReport_t m_Patterns;
	PeHeadersReport_t m_PeHeaders;
};

struct ScannerContext_t
{
	char m_szPath[MAX_PATH];
	u8 m_rgubWindow[0x2000];
	u32 m_unUnused0;
	u64 m_ulWindowBase;
	u32 m_ibWindow;
	u32 m_cubWindow;
	u64 m_ulClampStart;
	u64 m_ulClampEnd;
	HANDLE m_hFile;
	HANDLE m_hProcess;
	u64 m_ulMappedBase;
	u64 m_ulRelocationBase;
	u64 m_ulImageDelta;
	u32 m_cubMapped;
	u8 m_bZeroRelocations;
	u8 m_bPe64;
	IMAGE_DOS_HEADER m_DosHeader;
	u8 m_rgubUnused1[2];
	u8 m_rgubDosStub[144];
	IMAGE_FILE_HEADER m_RawFileHeader;
	IMAGE_FILE_HEADER m_FileHeader;
	IMAGE_OPTIONAL_HEADER32 m_OptionalHeader32;
	IMAGE_OPTIONAL_HEADER64 m_OptionalHeader64;
	IMAGE_SECTION_HEADER *m_pSections;
	void **m_ppSectionData;
	u8 m_rgubUnused2[40];
	IMAGE_DEBUG_DIRECTORY m_DebugDirectory;
	u8 m_rgubPdbGuid[16];
	char m_szPdbPath[260];
	u32 m_unUnused3;
	u32 m_cRelocationsApplied;
	u8 m_bUnused4;
	u8 m_rgubUnused5[0x2684 - 0x2581];
	i32 m_cResourceEntries;
	void **m_ppResourceData;
	void *m_pResourceTable;
	u8 *m_pubRelocations;
	u32 m_cubRelocations;
	i32 m_cSectionBuffers;
	void *m_rgpSectionBuffers[32];
	u32 m_unUnused6;
	u32 m_cubSection;
	u32 m_unSectionRva;
	u32 m_ibRelocationCursor;
	u8 m_bLoadedImagePass;
	u8 m_rgubUnused7[3];
	u32 m_unWinTrustStatus;
	u32 m_unWinTrustLastError;
	u32 m_unCertLastError;
	u32 m_unMappingLastError;
	verify::CertIdentity_t m_Signer;
	verify::CertIdentity_t m_Issuer;
	u8 m_bCatalogValid;
	char m_szCatalogPath[MAX_PATH];
	u8 m_rgubUnused8[3];
};

struct ProbeModule_t
{
	u32 m_cubImage;
	u32 m_unUnused;
	u64 m_ulBase;
	u32 m_iLoadOrder;
	wchar_t m_wszBaseName[256];
	wchar_t m_wszFullName[MAX_PATH];
	u8 m_rgubUnused[4];
};

struct ProbeThread_t
{
	THREADENTRY32 m_Entry;
	u32 m_unStartAddress;
};

struct ProcessProbe_t
{
	u8 m_rgubUnused0[0x22C];
	u32 m_unPid;
	HANDLE m_hProcess;
	u32 m_unLastError;
	process::ECaptureFlags m_eFlags;
	u32 m_unUnused1;
	u64 m_ulCreationTime;
	i32 m_cModules;
	ProbeModule_t *m_pModules;
	i32 m_cThreads;
	ProbeThread_t *m_pThreads;
	u32 m_unUnused2;
	void *m_pUnusedTableA;
	u32 m_unUnused3;
	void *m_pUnusedTableB;
	u8 m_rgubUnused4[20];
	void *m_pThreadStacks;
	nt::Peb32_t m_Peb;
	u32 m_unParentPid;
	nt::ProcessParameters32_t m_ProcessParameters;
	u8 m_rgubParametersTail[nt::Arch32_t::k_cubProcessParametersSnapshot - sizeof( nt::ProcessParameters32_t )];
	u8 m_bCrossBitness;
	u8 m_bSelfWow64;
	wchar_t m_wszCurrentDirectory[500];
	wchar_t m_wszImagePath[500];
	wchar_t m_wszCommandLine[1024];
	u8 m_rgubUnused5[2];
};

#pragma pack( pop )

VAC_LAYOUT( Input_t, m_unFlags, 0x20 );
VAC_LAYOUT( Input_t, m_unPid, 0x60 );
VAC_LAYOUT( Input_t, m_ulTarget, 0x64 );
VAC_LAYOUT( Input_t, m_unVolumeSerial, 0x6C );
VAC_LAYOUT_SIZE( Input_t, 160 );

VAC_LAYOUT_SIZE( SectionRecord_t, 24 );
VAC_LAYOUT( ModuleReport_t, m_cubImage, 16 );
VAC_LAYOUT( ModuleReport_t, m_cSections, 32 );
VAC_LAYOUT( ModuleReport_t, m_cubStream, 36 );
VAC_LAYOUT( ModuleReport_t, m_rgcubSections, 52 );
VAC_LAYOUT( ModuleReport_t, m_rgubStreamMd5, 100 );
VAC_LAYOUT( ModuleReport_t, m_rgubIconMd5, 148 );
VAC_LAYOUT( ModuleReport_t, m_rgubSectionMd5, 164 );
VAC_LAYOUT( ModuleReport_t, m_rgSections, 356 );
VAC_LAYOUT( ModuleReport_t, m_szPdbPath, 644 );
VAC_LAYOUT_SIZE( ModuleReport_t, 0x404 );

VAC_LAYOUT( PeHeadersReport_t, m_rgubOptionalHeader, 20 );
VAC_LAYOUT( PeHeadersReport_t, m_bCatalogValid, 260 );
VAC_LAYOUT( PeHeadersReport_t, m_rgubOverlayHead, 264 );
VAC_LAYOUT( PeHeadersReport_t, m_rgubDosStub, 272 );
VAC_LAYOUT( PeHeadersReport_t, m_unWinTrustStatus, 288 );
VAC_LAYOUT( PeHeadersReport_t, m_szCatalogPath, 296 );
VAC_LAYOUT( PeHeadersReport_t, m_Issuer, 356 );
VAC_LAYOUT_SIZE( PeHeadersReport_t, 0x1A0 );

VAC_LAYOUT( PatternReport_t, m_cubText, 0x20 );
VAC_LAYOUT( PatternReport_t, m_szText, 0x28 );
VAC_LAYOUT_SIZE( PatternReport_t, 0x4D8 );

VAC_LAYOUT( Report_t, m_eStatus, 0x10 );
VAC_LAYOUT( Report_t, m_ulCreationTime, 0x18 );
VAC_LAYOUT( Report_t, m_Primary, 0x20 );
VAC_LAYOUT( Report_t, m_Secondary, 0x424 );
VAC_LAYOUT( Report_t, m_szMappedPath, 0x828 );
VAC_LAYOUT( Report_t, m_unVolumeSerial, 0x928 );
VAC_LAYOUT( Report_t, m_ulFileIndex, 0x92C );
VAC_LAYOUT( Report_t, m_bFsRedirectionDisabled, 0x934 );
VAC_LAYOUT( Report_t, m_unReportVersion, 0x938 );
VAC_LAYOUT( Report_t, m_unLastError, 0x93C );
VAC_LAYOUT( Report_t, m_Patterns, 0x940 );
VAC_LAYOUT( Report_t, m_PeHeaders, 0xE18 );
VAC_LAYOUT_SIZE( Report_t, 0xFB8 );

VAC_LAYOUT( ScannerContext_t, m_rgubWindow, 0x104 );
VAC_LAYOUT( ScannerContext_t, m_ulWindowBase, 0x2108 );
VAC_LAYOUT( ScannerContext_t, m_ibWindow, 0x2110 );
VAC_LAYOUT( ScannerContext_t, m_ulClampStart, 0x2118 );
VAC_LAYOUT( ScannerContext_t, m_hFile, 0x2128 );
VAC_LAYOUT( ScannerContext_t, m_ulMappedBase, 0x2130 );
VAC_LAYOUT( ScannerContext_t, m_ulRelocationBase, 0x2138 );
VAC_LAYOUT( ScannerContext_t, m_ulImageDelta, 0x2140 );
VAC_LAYOUT( ScannerContext_t, m_cubMapped, 0x2148 );
VAC_LAYOUT( ScannerContext_t, m_bPe64, 0x214D );
VAC_LAYOUT( ScannerContext_t, m_DosHeader, 0x214E );
VAC_LAYOUT( ScannerContext_t, m_rgubDosStub, 0x2190 );
VAC_LAYOUT( ScannerContext_t, m_RawFileHeader, 0x2220 );
VAC_LAYOUT( ScannerContext_t, m_FileHeader, 0x2234 );
VAC_LAYOUT( ScannerContext_t, m_OptionalHeader32, 0x2248 );
VAC_LAYOUT( ScannerContext_t, m_OptionalHeader64, 0x2328 );
VAC_LAYOUT( ScannerContext_t, m_pSections, 0x2418 );
VAC_LAYOUT( ScannerContext_t, m_DebugDirectory, 0x2448 );
VAC_LAYOUT( ScannerContext_t, m_szPdbPath, 0x2474 );
VAC_LAYOUT( ScannerContext_t, m_cRelocationsApplied, 0x257C );
VAC_LAYOUT( ScannerContext_t, m_cResourceEntries, 0x2684 );
VAC_LAYOUT( ScannerContext_t, m_pubRelocations, 0x2690 );
VAC_LAYOUT( ScannerContext_t, m_rgpSectionBuffers, 0x269C );
VAC_LAYOUT( ScannerContext_t, m_cubSection, 0x2720 );
VAC_LAYOUT( ScannerContext_t, m_bLoadedImagePass, 0x272C );
VAC_LAYOUT( ScannerContext_t, m_unWinTrustStatus, 0x2730 );
VAC_LAYOUT( ScannerContext_t, m_Signer, 0x2740 );
VAC_LAYOUT( ScannerContext_t, m_Issuer, 0x277C );
VAC_LAYOUT( ScannerContext_t, m_bCatalogValid, 0x27B8 );
VAC_LAYOUT( ScannerContext_t, m_szCatalogPath, 0x27B9 );
VAC_LAYOUT_SIZE( ScannerContext_t, 0x28C0 );

VAC_LAYOUT( ProbeModule_t, m_ulBase, 0x08 );
VAC_LAYOUT( ProbeModule_t, m_wszBaseName, 0x14 );
VAC_LAYOUT( ProbeModule_t, m_wszFullName, 0x214 );
VAC_LAYOUT_SIZE( ProbeModule_t, 0x420 );
VAC_LAYOUT( ProbeThread_t, m_unStartAddress, 0x1C );
VAC_LAYOUT_SIZE( ProbeThread_t, 0x20 );

VAC_LAYOUT( ProcessProbe_t, m_unPid, 0x22C );
VAC_LAYOUT( ProcessProbe_t, m_hProcess, 0x230 );
VAC_LAYOUT( ProcessProbe_t, m_unLastError, 0x234 );
VAC_LAYOUT( ProcessProbe_t, m_eFlags, 0x238 );
VAC_LAYOUT( ProcessProbe_t, m_ulCreationTime, 0x240 );
VAC_LAYOUT( ProcessProbe_t, m_cModules, 0x248 );
VAC_LAYOUT( ProcessProbe_t, m_cThreads, 0x250 );
VAC_LAYOUT( ProcessProbe_t, m_pThreadStacks, 0x27C );
VAC_LAYOUT( ProcessProbe_t, m_Peb, 0x280 );
VAC_LAYOUT( ProcessProbe_t, m_unParentPid, 0x454 );
VAC_LAYOUT( ProcessProbe_t, m_ProcessParameters, 0x458 );
VAC_LAYOUT( ProcessProbe_t, m_bCrossBitness, 0x4A4 );
VAC_LAYOUT( ProcessProbe_t, m_wszCurrentDirectory, 0x4A6 );
VAC_LAYOUT( ProcessProbe_t, m_wszImagePath, 0x88E );
VAC_LAYOUT( ProcessProbe_t, m_wszCommandLine, 0xC76 );
VAC_LAYOUT_SIZE( ProcessProbe_t, 0x1478 );

struct ScanSession_t
{
	ProcessProbe_t *m_pProbe;
	u32 m_rgunUnused[3];
	void *m_pvScratch;
};

int RunImageScan( const Input_t &input, Report_t &report, u32 *pcubOutput ) noexcept;

} // namespace vac::workers::image_scan
