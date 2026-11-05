#pragma once

#include "bootstrap/imports.hpp"
#include "core/enum.hpp"
#include "core/layout.hpp"
#include "core/packets.hpp"
#include "core/scan_status.hpp"
#include "crypto/hash/md5.hpp"
#include "nt/nt.hpp"
#include "process/capture_flags.hpp"
#include "verify/cert_chain.hpp"

namespace vac::workers::process_file_identity
{

inline constexpr u32 k_unProcessModuleId = 0x0B2D8276;
inline constexpr u32 k_unFileModuleId = 0x013B4330;
inline constexpr u32 k_unDirectoryModuleId = 0x0CA11165;

inline constexpr u32 k_unDirectoryMagic = 0xEDF00ABC;
inline constexpr u32 k_unVlvSignature = 0x564C56;
inline constexpr u32 k_unUnsetError = 8675309;
inline constexpr u32 k_cPathChars = 512;

enum class EEntryFlags : u16
{
	None = 0,
	Directory = 0x0001,
	OtherAttributes = 0x0002,
	Hidden = 0x0004,
	ReadOnly = 0x0008,
	System = 0x0010,
	AgeTier0 = 0x0080,
	AgeTier3 = 0x0100,
	AgeTier2 = 0x0200,
	AgeTier1 = 0x0400,
	NeverWritten = 0x0800,
	Empty = 0x1000,
	Small = 0x2000,
	Large = 0x4000,
};
VAC_FLAGS( EEntryFlags )

// @note / sapdragon: only modules and parameters do anything, valve's encoder maps the other bits for nobody
enum class ECaptureRequest : u16
{
	None = 0,
	Modules = 0x010,
	Parameters = 0x020,
	Unused040 = 0x040,
	Unused080 = 0x080,
	Unused100 = 0x100,
	Unused200 = 0x200,
};
VAC_FLAGS( ECaptureRequest )

enum class ECaptureOptions : u8
{
	None = 0,
	Modules = 0x01,
	Unused02 = 0x02,
	Parameters = 0x04,
	Unused08 = 0x08,
	Unused10 = 0x10,
	Unused20 = 0x20,
};
VAC_FLAGS( ECaptureOptions )

#pragma pack( push, 1 )
struct FileId_t
{
	u32 m_unLow;
	u32 m_unHigh;
};
VAC_LAYOUT_SIZE( FileId_t, 8 );

// @note / sapdragon: a byte count, or the top bit when that digest could not be built
struct DigestSize_t
{
	u32 m_cubHashed : 31;
	u32 m_bFailed : 1;
};
VAC_LAYOUT_SIZE( DigestSize_t, 4 );

struct ProcessInput_t
{
	u8 m_rgubBootstrap[96];
	u32 m_unPid;
	u8 m_rgubReserved[60];
};
VAC_LAYOUT( ProcessInput_t, m_unPid, 0x60 );
VAC_LAYOUT_SIZE( ProcessInput_t, 160 );

struct FileInput_t
{
	u8 m_rgubBootstrap[32];
	char m_szPath[128];
};
VAC_LAYOUT( FileInput_t, m_szPath, 0x20 );
VAC_LAYOUT_SIZE( FileInput_t, 160 );

struct DirectoryInput_t
{
	u8 m_rgubBootstrap[36];
	u32 m_unVolume;
	FileId_t m_FileId;
	u32 m_unIncludeMask;
	u32 m_unExcludeMask;
	char m_szPath[104];
};
VAC_LAYOUT( DirectoryInput_t, m_unVolume, 0x24 );
VAC_LAYOUT( DirectoryInput_t, m_FileId, 0x28 );
VAC_LAYOUT( DirectoryInput_t, m_unIncludeMask, 0x30 );
VAC_LAYOUT( DirectoryInput_t, m_unExcludeMask, 0x34 );
VAC_LAYOUT( DirectoryInput_t, m_szPath, 0x38 );
VAC_LAYOUT_SIZE( DirectoryInput_t, 160 );

struct ImageFingerprints_t
{
	u8 m_rgubImageDigest[crypto::hash::k_cubMd5Digest];
	u8 m_rgubCodeDigest[crypto::hash::k_cubMd5Digest];
	u8 m_rgubUnused[48];
	u32 m_unTimeDateStamp;
	u32 m_unCheckSum;
	u32 m_unVlvSignature;
};
VAC_LAYOUT( ImageFingerprints_t, m_rgubCodeDigest, 16 );
VAC_LAYOUT( ImageFingerprints_t, m_unTimeDateStamp, 80 );
VAC_LAYOUT( ImageFingerprints_t, m_unCheckSum, 84 );
VAC_LAYOUT( ImageFingerprints_t, m_unVlvSignature, 88 );
VAC_LAYOUT_SIZE( ImageFingerprints_t, 92 );

struct SectionRow_t
{
	u32 m_cubRawData;
	u32 m_unVirtualAddress;
	u32 m_unCharacteristics;
	u32 m_unZero;
	u8 m_rgubName[IMAGE_SIZEOF_SHORT_NAME];
};
VAC_LAYOUT( SectionRow_t, m_rgubName, 16 );
VAC_LAYOUT_SIZE( SectionRow_t, 24 );

struct ImageDetails_t
{
	u8 m_rgubUnused0[20];
	u32 m_unTimeDateStamp;
	u32 m_unCheckSum;
	u32 m_unEntryPoint;
	u8 m_cSections;
	u8 m_rgubUnused1[2];
	u8 m_cReportedSections;
	u8 m_rgubUnused2[4];
	DigestSize_t m_LayoutDigestSize;
	DigestSize_t m_ImageDigestSize;
	DigestSize_t m_IconDigestSize;
	DigestSize_t m_rgSectionDigestSizes[12];
	u8 m_rgubUnused3[16];
	u8 m_rgubLayoutDigest[crypto::hash::k_cubMd5Digest];
	u8 m_rgubImageDigest[crypto::hash::k_cubMd5Digest];
	u8 m_rgubIconDigest[crypto::hash::k_cubMd5Digest];
	u8 m_rgrgubSectionDigests[12][crypto::hash::k_cubMd5Digest];
	SectionRow_t m_rgSections[12];
	char m_szPdbPath[MAX_PATH];
	u8 m_rgubUnused4[124];
};
VAC_LAYOUT( ImageDetails_t, m_unTimeDateStamp, 20 );
VAC_LAYOUT( ImageDetails_t, m_unCheckSum, 24 );
VAC_LAYOUT( ImageDetails_t, m_unEntryPoint, 28 );
VAC_LAYOUT( ImageDetails_t, m_cSections, 32 );
VAC_LAYOUT( ImageDetails_t, m_cReportedSections, 35 );
VAC_LAYOUT( ImageDetails_t, m_LayoutDigestSize, 40 );
VAC_LAYOUT( ImageDetails_t, m_ImageDigestSize, 44 );
VAC_LAYOUT( ImageDetails_t, m_IconDigestSize, 48 );
VAC_LAYOUT( ImageDetails_t, m_rgSectionDigestSizes, 52 );
VAC_LAYOUT( ImageDetails_t, m_rgubLayoutDigest, 116 );
VAC_LAYOUT( ImageDetails_t, m_rgubImageDigest, 132 );
VAC_LAYOUT( ImageDetails_t, m_rgubIconDigest, 148 );
VAC_LAYOUT( ImageDetails_t, m_rgrgubSectionDigests, 164 );
VAC_LAYOUT( ImageDetails_t, m_rgSections, 356 );
VAC_LAYOUT( ImageDetails_t, m_szPdbPath, 644 );
VAC_LAYOUT_SIZE( ImageDetails_t, 1028 );

struct ImageHeaders_t
{
	IMAGE_FILE_HEADER m_FileHeader;
	u8 m_rgubOptionalHeader[224];
	u8 m_rgubUnused[20];
	u8 m_rgubOverlayStart[8];
	u8 m_rgubDosStub[16];
	u32 m_unTrustStatus;
	u32 m_unTrustError;
	verify::CertIdentity_t m_Signer;
	verify::CertIdentity_t m_Issuer;
};
VAC_LAYOUT( ImageHeaders_t, m_rgubOptionalHeader, 20 );
VAC_LAYOUT( ImageHeaders_t, m_rgubOverlayStart, 264 );
VAC_LAYOUT( ImageHeaders_t, m_rgubDosStub, 272 );
VAC_LAYOUT( ImageHeaders_t, m_unTrustStatus, 288 );
VAC_LAYOUT( ImageHeaders_t, m_unTrustError, 292 );
VAC_LAYOUT( ImageHeaders_t, m_Signer, 296 );
VAC_LAYOUT( ImageHeaders_t, m_Issuer, 356 );
VAC_LAYOUT_SIZE( ImageHeaders_t, 416 );

struct ProcessReport_t
{
	u8 m_rgubDispatcher[16];
	EScanStatus m_eStatus;
	u8 m_rgubUnused0[12];
	ImageFingerprints_t m_Fingerprints;
	u8 m_rgubUnused1[4];
	u32 m_unPid;
	u32 m_unParentPid;
	EScanStatus m_eOpenStatus;
	u32 m_unProbeError;
	u32 m_unImageFileNameError;
	EScanStatus m_eProbeStatus;
	u8 m_rgubUnused2[4];
	u32 m_unFullImageNameError;
	EScanStatus m_ePeStatus;
	u32 m_unSessionId;
	char m_szUserSid[56];
	char m_szCurrentDirectory[240];
	FileId_t m_CurrentDirectoryId;
	u32 m_unCurrentDirectoryVolume;
	u32 m_unPeError;
	char m_szCommandLine[256];
	char m_szImagePath[256];
	char m_szVersionStrings[1024];
	u32 m_unDetailType;
	ImageDetails_t m_Details;
	ImageHeaders_t m_Headers;
	u8 m_rgubUnused3[632];
};
VAC_LAYOUT( ProcessReport_t, m_eStatus, 0x10 );
VAC_LAYOUT( ProcessReport_t, m_Fingerprints, 0x20 );
VAC_LAYOUT( ProcessReport_t, m_unPid, 0x80 );
VAC_LAYOUT( ProcessReport_t, m_unParentPid, 0x84 );
VAC_LAYOUT( ProcessReport_t, m_eOpenStatus, 0x88 );
VAC_LAYOUT( ProcessReport_t, m_unProbeError, 0x8C );
VAC_LAYOUT( ProcessReport_t, m_unImageFileNameError, 0x90 );
VAC_LAYOUT( ProcessReport_t, m_eProbeStatus, 0x94 );
VAC_LAYOUT( ProcessReport_t, m_unFullImageNameError, 0x9C );
VAC_LAYOUT( ProcessReport_t, m_ePeStatus, 0xA0 );
VAC_LAYOUT( ProcessReport_t, m_unSessionId, 0xA4 );
VAC_LAYOUT( ProcessReport_t, m_szUserSid, 0xA8 );
VAC_LAYOUT( ProcessReport_t, m_szCurrentDirectory, 0xE0 );
VAC_LAYOUT( ProcessReport_t, m_CurrentDirectoryId, 0x1D0 );
VAC_LAYOUT( ProcessReport_t, m_unCurrentDirectoryVolume, 0x1D8 );
VAC_LAYOUT( ProcessReport_t, m_unPeError, 0x1DC );
VAC_LAYOUT( ProcessReport_t, m_szCommandLine, 0x1E0 );
VAC_LAYOUT( ProcessReport_t, m_szImagePath, 0x2E0 );
VAC_LAYOUT( ProcessReport_t, m_szVersionStrings, 0x3E0 );
VAC_LAYOUT( ProcessReport_t, m_unDetailType, 0x7E0 );
VAC_LAYOUT( ProcessReport_t, m_Details, 0x7E4 );
VAC_LAYOUT( ProcessReport_t, m_Headers, 0xBE8 );
VAC_LAYOUT( ProcessReport_t, m_rgubUnused3, 0xD88 );
VAC_LAYOUT_SIZE( ProcessReport_t, k_cubReport );

struct FileReport_t
{
	u8 m_rgubDispatcher[16];
	EScanStatus m_eStatus;
	u8 m_rgubUnused0[4];
	EScanStatus m_eOpenStatus;
	u32 m_unOpenError;
	EScanStatus m_ePeStatus;
	u32 m_cubFile;
	FileId_t m_FileId;
	u32 m_unVolume;
	u32 m_unIdentityError;
	union
	{
		// @note / sapdragon: 17 ancestors do not fit, the last one lands on the start of the path. valve's loop does that
		FileId_t m_rgAncestors[17];
		struct
		{
			u8 m_rgubUnused1[128];
			char m_szPath[128];
		};
	};
	u8 m_rgubUnused2[3784];
};
VAC_LAYOUT( FileReport_t, m_eStatus, 0x10 );
VAC_LAYOUT( FileReport_t, m_eOpenStatus, 0x18 );
VAC_LAYOUT( FileReport_t, m_unOpenError, 0x1C );
VAC_LAYOUT( FileReport_t, m_ePeStatus, 0x20 );
VAC_LAYOUT( FileReport_t, m_cubFile, 0x24 );
VAC_LAYOUT( FileReport_t, m_FileId, 0x28 );
VAC_LAYOUT( FileReport_t, m_unVolume, 0x30 );
VAC_LAYOUT( FileReport_t, m_unIdentityError, 0x34 );
VAC_LAYOUT( FileReport_t, m_rgAncestors, 0x38 );
VAC_LAYOUT( FileReport_t, m_szPath, 0xB8 );
VAC_LAYOUT( FileReport_t, m_rgubUnused2, 0x138 );
VAC_LAYOUT_SIZE( FileReport_t, k_cubReport );

struct DirectoryRecord_t
{
	FileId_t m_FileId;
	u32 m_unNameHash;
	EEntryFlags m_eFlags;
	u8 m_iParent;
	u8 m_iDirectory;
	u32 m_unCreationTime;
};
VAC_LAYOUT( DirectoryRecord_t, m_unNameHash, 8 );
VAC_LAYOUT( DirectoryRecord_t, m_eFlags, 12 );
VAC_LAYOUT( DirectoryRecord_t, m_iParent, 14 );
VAC_LAYOUT( DirectoryRecord_t, m_iDirectory, 15 );
VAC_LAYOUT( DirectoryRecord_t, m_unCreationTime, 16 );
VAC_LAYOUT_SIZE( DirectoryRecord_t, 20 );

struct DirectoryReport_t
{
	u8 m_rgubDispatcher[16];
	u32 m_unMagic;
	EScanStatus m_eStatus;
	u32 m_unVersion;
	u32 m_unOpenError;
	u32 m_unInfoError;
	u32 m_cProfileChars;
	u32 m_cRecords;
	u32 m_cDirectories;
	u32 m_unVolume;
	u32 m_unMismatchedVolume;
	FileId_t m_RootId;
	u32 m_unReserved;
	u32 m_unProfileHash;
	u32 m_unProfileNameHash;
	// @note / sapdragon: only 16 bits on the wire, so these two hold an EScanStatus as a plain number
	u16 m_unScanStatus;
	u16 m_unExpandStatus;
	u32 m_unProfilePid;
	u32 m_cSkipped;
	u32 m_cSkippedInRoot;
	u16 m_cExpanded;
	u16 m_iExpanded;
	DirectoryRecord_t m_rgRecords[200];
};
VAC_LAYOUT( DirectoryReport_t, m_unMagic, 0x10 );
VAC_LAYOUT( DirectoryReport_t, m_eStatus, 0x14 );
VAC_LAYOUT( DirectoryReport_t, m_unVersion, 0x18 );
VAC_LAYOUT( DirectoryReport_t, m_unOpenError, 0x1C );
VAC_LAYOUT( DirectoryReport_t, m_unInfoError, 0x20 );
VAC_LAYOUT( DirectoryReport_t, m_cProfileChars, 0x24 );
VAC_LAYOUT( DirectoryReport_t, m_cRecords, 0x28 );
VAC_LAYOUT( DirectoryReport_t, m_cDirectories, 0x2C );
VAC_LAYOUT( DirectoryReport_t, m_unVolume, 0x30 );
VAC_LAYOUT( DirectoryReport_t, m_unMismatchedVolume, 0x34 );
VAC_LAYOUT( DirectoryReport_t, m_RootId, 0x38 );
VAC_LAYOUT( DirectoryReport_t, m_unReserved, 0x40 );
VAC_LAYOUT( DirectoryReport_t, m_unProfileHash, 0x44 );
VAC_LAYOUT( DirectoryReport_t, m_unProfileNameHash, 0x48 );
VAC_LAYOUT( DirectoryReport_t, m_unScanStatus, 0x4C );
VAC_LAYOUT( DirectoryReport_t, m_unExpandStatus, 0x4E );
VAC_LAYOUT( DirectoryReport_t, m_unProfilePid, 0x50 );
VAC_LAYOUT( DirectoryReport_t, m_cSkipped, 0x54 );
VAC_LAYOUT( DirectoryReport_t, m_cSkippedInRoot, 0x58 );
VAC_LAYOUT( DirectoryReport_t, m_cExpanded, 0x5C );
VAC_LAYOUT( DirectoryReport_t, m_iExpanded, 0x5E );
VAC_LAYOUT( DirectoryReport_t, m_rgRecords, 0x60 );
VAC_LAYOUT_SIZE( DirectoryReport_t, k_cubReport );

struct PeFile_t
{
	char m_szPath[260];
	u8 m_rgubWindow[0x2000];
	u8 m_rgubUnused0[4];
	u64 m_ulWindowBase;
	u32 m_ibCursor;
	u32 m_cubWindow;
	u64 m_ulRangeStart;
	u64 m_ulRangeEnd;
	HANDLE m_hFile;
	HANDLE m_hProcess;
	u64 m_ulMappedBase;
	u64 m_ulImageBase;
	u64 m_ulRelocationDelta;
	u8 m_rgubUnused1[5];
	u8 m_bPe64;
	IMAGE_DOS_HEADER m_DosHeader;
	u8 m_rgubUnused2[2];
	u8 m_rgubDosStub[144];
	IMAGE_FILE_HEADER m_OriginalFileHeader;
	IMAGE_FILE_HEADER m_FileHeader;
	IMAGE_OPTIONAL_HEADER32 m_OptionalHeader32;
	IMAGE_OPTIONAL_HEADER64 m_OptionalHeader64;
	IMAGE_SECTION_HEADER *m_pSections;
	u8 m_rgubUnused3[44];
	IMAGE_DEBUG_DIRECTORY m_DebugDirectory;
	u8 m_rgubPdbGuid[16];
	char m_szPdbPath[MAX_PATH];
	u8 m_rgubUnused4[4];
	u32 m_cRelocationsApplied;
	u8 m_rgubUnused5[272];
	u8 *m_pubRelocations;
	u32 m_cubRelocations;
	u8 m_rgubUnused6[136];
	u32 m_cubSectionRemaining;
	u32 m_unSectionRva;
	u32 m_ibRelocationCursor;
	u8 m_bLayoutDigest;
	u8 m_rgubUnused7[3];
	u32 m_unTrustStatus;
	u32 m_unTrustError;
	verify::CertIdentity_t m_Signer;
	verify::CertIdentity_t m_Issuer;
};
VAC_LAYOUT( PeFile_t, m_rgubWindow, 260 );
VAC_LAYOUT( PeFile_t, m_ulWindowBase, 8456 );
VAC_LAYOUT( PeFile_t, m_ibCursor, 8464 );
VAC_LAYOUT( PeFile_t, m_cubWindow, 8468 );
VAC_LAYOUT( PeFile_t, m_ulRangeStart, 8472 );
VAC_LAYOUT( PeFile_t, m_ulRangeEnd, 8480 );
VAC_LAYOUT( PeFile_t, m_hFile, 8488 );
VAC_LAYOUT( PeFile_t, m_hProcess, 8492 );
VAC_LAYOUT( PeFile_t, m_ulMappedBase, 8496 );
VAC_LAYOUT( PeFile_t, m_ulImageBase, 8504 );
VAC_LAYOUT( PeFile_t, m_ulRelocationDelta, 8512 );
VAC_LAYOUT( PeFile_t, m_bPe64, 8525 );
VAC_LAYOUT( PeFile_t, m_DosHeader, 8526 );
VAC_LAYOUT( PeFile_t, m_rgubDosStub, 8592 );
VAC_LAYOUT( PeFile_t, m_OriginalFileHeader, 8736 );
VAC_LAYOUT( PeFile_t, m_FileHeader, 8756 );
VAC_LAYOUT( PeFile_t, m_OptionalHeader32, 8776 );
VAC_LAYOUT( PeFile_t, m_OptionalHeader64, 9000 );
VAC_LAYOUT( PeFile_t, m_pSections, 9240 );
VAC_LAYOUT( PeFile_t, m_DebugDirectory, 9288 );
VAC_LAYOUT( PeFile_t, m_rgubPdbGuid, 9316 );
VAC_LAYOUT( PeFile_t, m_szPdbPath, 9332 );
VAC_LAYOUT( PeFile_t, m_cRelocationsApplied, 9596 );
VAC_LAYOUT( PeFile_t, m_pubRelocations, 9872 );
VAC_LAYOUT( PeFile_t, m_cubRelocations, 9876 );
VAC_LAYOUT( PeFile_t, m_cubSectionRemaining, 10016 );
VAC_LAYOUT( PeFile_t, m_unSectionRva, 10020 );
VAC_LAYOUT( PeFile_t, m_ibRelocationCursor, 10024 );
VAC_LAYOUT( PeFile_t, m_bLayoutDigest, 10028 );
VAC_LAYOUT( PeFile_t, m_unTrustStatus, 10032 );
VAC_LAYOUT( PeFile_t, m_unTrustError, 10036 );
VAC_LAYOUT( PeFile_t, m_Signer, 10040 );
VAC_LAYOUT( PeFile_t, m_Issuer, 10100 );
VAC_LAYOUT_SIZE( PeFile_t, 10160 );

struct ModuleRecord_t
{
	u32 m_unTag;
	u8 m_rgubUnused[4];
	u64 m_ulBase;
	wchar_t m_wszName[256];
	wchar_t m_wszPath[260];
};
VAC_LAYOUT( ModuleRecord_t, m_ulBase, 8 );
VAC_LAYOUT( ModuleRecord_t, m_wszName, 16 );
VAC_LAYOUT( ModuleRecord_t, m_wszPath, 528 );
VAC_LAYOUT_SIZE( ModuleRecord_t, 1048 );

struct ProcessCapture_t
{
	u8 m_rgubUnused0[556];
	u32 m_unPid;
	HANDLE m_hProcess;
	u32 m_unLastError;
	// @note / sapdragon: nothing reads this, the original keeps it anyway
	process::ECaptureFlags m_eProgress;
	u8 m_rgubUnused1[4];
	FILETIME m_CreationTime;
	u32 m_cModules;
	ModuleRecord_t *m_pModules;
	u8 m_rgubUnused2[48];
	nt::Peb32_t m_Peb;
	u32 m_unParentPid;
	union
	{
		nt::ProcessParameters32_t m_Parameters;
		u8 m_rgubParameters[nt::Arch32_t::k_cubProcessParametersSnapshot];
	};
	u8 m_bTargetIsNative64;
	u8 m_bSelfIsWow64;
	wchar_t m_wszCurrentDirectory[500];
	wchar_t m_wszImagePath[500];
	wchar_t m_wszCommandLine[500];
	u8 m_rgubUnused3[2];
};
VAC_LAYOUT( ProcessCapture_t, m_unPid, 556 );
VAC_LAYOUT( ProcessCapture_t, m_hProcess, 560 );
VAC_LAYOUT( ProcessCapture_t, m_unLastError, 564 );
VAC_LAYOUT( ProcessCapture_t, m_eProgress, 568 );
VAC_LAYOUT( ProcessCapture_t, m_CreationTime, 576 );
VAC_LAYOUT( ProcessCapture_t, m_cModules, 584 );
VAC_LAYOUT( ProcessCapture_t, m_pModules, 588 );
VAC_LAYOUT( ProcessCapture_t, m_Peb, 640 );
VAC_LAYOUT( ProcessCapture_t, m_unParentPid, 1108 );
VAC_LAYOUT( ProcessCapture_t, m_Parameters, 1112 );
VAC_LAYOUT( ProcessCapture_t, m_bTargetIsNative64, 1188 );
VAC_LAYOUT( ProcessCapture_t, m_bSelfIsWow64, 1189 );
VAC_LAYOUT( ProcessCapture_t, m_wszCurrentDirectory, 1190 );
VAC_LAYOUT( ProcessCapture_t, m_wszImagePath, 2190 );
VAC_LAYOUT( ProcessCapture_t, m_wszCommandLine, 3190 );
VAC_LAYOUT_SIZE( ProcessCapture_t, 0x1060 );
#pragma pack( pop )

int CompareNoCaseN( const wchar_t *pwszA, const wchar_t *pwszB, int cChars ) noexcept;
void CopyWideFixed( wchar_t *pwszDst, const wchar_t *pwszSrc, u32 cChars ) noexcept;
void CatWideBounded( wchar_t *pwszDst, const wchar_t *pwszSrc, u32 cMaxChars ) noexcept;
void *ReallocateHeap( void *pMemory, usize cubSize ) noexcept;
u32 BoundedPathLength( const char *pszPath ) noexcept;
bool NtDeviceToDosPath( wchar_t *pwszPath ) noexcept;
u32 CollectVersionStrings( const wchar_t *pwszPath, char *pszOutput ) noexcept;
bool QueryFileIdentity( const wchar_t *pwszPath, bool bDirectory, u32 *punVolume, FileId_t *pFileId ) noexcept;

void InitPeFile( PeFile_t &file ) noexcept;
void ClosePeFile( PeFile_t &file ) noexcept;
void ResetPeFile( PeFile_t &file ) noexcept;
EScanStatus OpenPeFile( PeFile_t &file, const wchar_t *pwszPath ) noexcept;
EScanStatus ParsePeFile( PeFile_t &file ) noexcept;
void BuildImageFingerprints( PeFile_t &file, ImageFingerprints_t &fingerprints ) noexcept;
void BuildImageDetails( PeFile_t &file, ImageDetails_t &details ) noexcept;
void ExportImageHeaders( PeFile_t &file, ImageHeaders_t &headers ) noexcept;

ECaptureOptions EncodeCaptureFlags( ECaptureRequest eRequest ) noexcept;
void InitProcessCapture( ProcessCapture_t &capture ) noexcept;
void FreeProcessCapture( ProcessCapture_t &capture ) noexcept;
EScanStatus CaptureProcess( ProcessCapture_t &capture, u32 unPid, ECaptureOptions eOptions ) noexcept;
bool GetFirstModulePath( u32 unPid, wchar_t *pwszPath ) noexcept;
void FindProfileProcess( u32 *punPid, u32 *pcFound ) noexcept;

u16 EnumerateDirectory( DirectoryReport_t &report, u32 unIncludeMask, u32 unExcludeMask, const wchar_t *pwszPath,
                        u32 unVolume, FileId_t fileId, u8 iParent ) noexcept;
void ExpandDirectories( DirectoryReport_t &report, u32 unIncludeMask, u32 unExcludeMask ) noexcept;

} // namespace vac::workers::process_file_identity
