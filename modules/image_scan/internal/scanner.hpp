#pragma once

#include "types.hpp"
#include "core/enum.hpp"
#include "crypto/hash/md5.hpp"

namespace vac::workers::image_scan
{

inline constexpr u32 k_cMaxMappedNameChars = 500;

enum class EHashMode : u32
{
	Md5 = 1,
	Lfsr = 2,
	Md5Rebased = 5,
	Md5RebasedAlt = 9,
};
VAC_FLAGS( EHashMode )

enum class EScanAccess : u32
{
	Modules = 0x10,
	Threads = 0x40,
};

enum class EProbeFlags : u8
{
	Modules = 0x01,
	Threads = 0x02,
	Parameters = 0x04,
	LoadOrder = 0x40,
	InitOrder = 0x80,
};
VAC_FLAGS( EProbeFlags )

enum class EMemoryInfoClass : DWORD
{
	MemoryBasicInformation = 0,
	MemoryMappedFilenameInformation = 2,
};

#pragma pack( push, 1 )
struct HybridHash_t
{
	crypto::hash::Md5_t m_Md5;
	u8 m_rgubDigest[16];
	u32 m_unLfsr;
	u32 m_cubTotal;
	EHashMode m_eMode;
	u8 m_rgubUnused[12];
};
#pragma pack( pop )
VAC_LAYOUT( HybridHash_t, m_rgubDigest, 88 );
VAC_LAYOUT( HybridHash_t, m_unLfsr, 104 );
VAC_LAYOUT( HybridHash_t, m_cubTotal, 108 );
VAC_LAYOUT( HybridHash_t, m_eMode, 112 );

struct RegionWalk_t
{
	u64 m_ulCursor;
	u64 m_ulNext;
	MEMORY_BASIC_INFORMATION64 m_First;
	u64 m_ulFirstCommitted;
	u64 m_ulCommittedEnd;
	u64 m_ulContiguousEnd;
	u64 m_ulCurrent;
	u32 m_unLastError;
	u32 m_unUnused0;
	u64 m_cubTotal;
	u32 m_unProtectMask;
	u32 m_unExecutableProtectMask;
	u32 m_cRegions;
	u32 m_cCommitted;
	u64 m_cubContiguous;
	u8 m_rgubUnused1[8];
};
VAC_LAYOUT( RegionWalk_t, m_First, 0x10 );
VAC_LAYOUT( RegionWalk_t, m_ulFirstCommitted, 0x40 );
VAC_LAYOUT( RegionWalk_t, m_unLastError, 0x60 );
VAC_LAYOUT( RegionWalk_t, m_cubTotal, 0x68 );
VAC_LAYOUT( RegionWalk_t, m_unProtectMask, 0x70 );
VAC_LAYOUT( RegionWalk_t, m_cRegions, 0x78 );
VAC_LAYOUT( RegionWalk_t, m_cubContiguous, 0x80 );
VAC_LAYOUT_SIZE( RegionWalk_t, 0x90 );

void *AllocBytes( u32 cub ) noexcept;
void FreeBytes( void *pv ) noexcept;
void *ReallocBytes( void *pv, u32 cub ) noexcept;

int CompareNameBounded( const char *pszA, const char *pszB, u32 cMaxChars ) noexcept;
int ComparePathPrefix( const wchar_t *pwszA, const wchar_t *pwszB, u32 cMaxChars ) noexcept;
void CopyWideFill( wchar_t *pwszDst, const wchar_t *pwszSrc, u32 cChars ) noexcept;
bool ResolveSpecialPath( const wchar_t *pwszPath, wchar_t *pwszResolved ) noexcept;
bool DevicePathToDos( wchar_t *pwszPath ) noexcept;
bool DisableWow64FsRedirection() noexcept;
bool GetFileVolumeAndIndex( const wchar_t *pwszPath, u32 *punVolumeSerial, u64 *pulFileIndex ) noexcept;

bool IsCrossBitnessProcess( HANDLE hProcess, BOOL *pbCrossBitness ) noexcept;
NTSTATUS QueryTargetMemory( HANDLE hProcess, u64 ulAddress, EMemoryInfoClass eInfoClass, void *pvBuffer, u64 cubBuffer,
                            u64 *pcubReturned ) noexcept;
NTSTATUS ReadTargetMemory( HANDLE hProcess, u64 ulAddress, void *pvBuffer, u64 cubBuffer, u64 *pcubRead ) noexcept;
u32 QueryTargetRegion( HANDLE hProcess, u64 ulAddress, MEMORY_BASIC_INFORMATION64 *pInfo ) noexcept;
u32 QueryTargetMappedName( HANDLE hProcess, u64 ulAddress, wchar_t *pwszName ) noexcept;

void CloseReader( ScannerContext_t *pCtx ) noexcept;
void SetReaderClamp( ScannerContext_t *pCtx, u64 ulStart, u64 ulEnd ) noexcept;
bool OpenFilePath( ScannerContext_t *pCtx, const wchar_t *pwszPath ) noexcept;
bool AttachFileHandle( ScannerContext_t *pCtx, HANDLE hFile ) noexcept;
const u8 *ReaderWindow( ScannerContext_t *pCtx, u32 cub ) noexcept;
bool ReaderReadBytes( ScannerContext_t *pCtx, void *pvDst, u32 cub ) noexcept;
bool ReaderSeek( ScannerContext_t *pCtx, u32 ibOffset, bool bForce ) noexcept;
u32 ReaderReadAt( ScannerContext_t *pCtx, u32 ibOffset, void *pvDst, u32 cub ) noexcept;

void InitScannerContext( ScannerContext_t *pCtx ) noexcept;
const IMAGE_SECTION_HEADER *FindExtraSection( const ScannerContext_t *pCtx ) noexcept;
EScanStatus ParsePeHeader( ScannerContext_t *pCtx ) noexcept;
EScanStatus SetMemoryMapping( ScannerContext_t *pCtx, u64 ulBase, u32 cubMapped, HANDLE hProcess ) noexcept;
EScanStatus OpenFileById( ScannerContext_t *pCtx, u32 unVolumeSerial, u64 ulFileId, u32 *punLastError ) noexcept;
EScanStatus DeepPeScan( ScannerContext_t *pCtx ) noexcept;
void CleanupScannerContext( ScannerContext_t *pCtx ) noexcept;

void ConstructHybridHash( HybridHash_t *pHash ) noexcept;
void ResetHybridHash( HybridHash_t *pHash ) noexcept;
void UpdateHybridHash( HybridHash_t *pHash, const void *pvData, u32 cubData ) noexcept;
u32 GetHybridHashResult( const HybridHash_t *pHash, void *pvDst ) noexcept;
bool HashSectionWithFixups( ScannerContext_t *pCtx, const IMAGE_SECTION_HEADER *pSection,
                            HybridHash_t *pHash ) noexcept;
bool HashAllSections( ScannerContext_t *pCtx, HybridHash_t *pHash ) noexcept;

EScanStatus ExtractPdbInfo( ScannerContext_t *pCtx ) noexcept;

bool HashBestIconResource( ScannerContext_t *pCtx, u8 *pubDigest, u32 *pcubIcon ) noexcept;

bool HashStreamAndScanPatterns( ScannerContext_t *pCtx, u32 cubStream, ModuleReport_t *pModule,
                                PatternReport_t *pPatterns ) noexcept;

void DumpModuleInfo( ScannerContext_t *pCtx, ModuleReport_t *pModule ) noexcept;
void DumpPeHeaders( ScannerContext_t *pCtx, PeHeadersReport_t *pPeHeaders ) noexcept;

bool VerifySignatureAndCatalog( ScannerContext_t *pCtx, bool bLookUpCatalog ) noexcept;

ProbeModule_t *FindModuleByPath( const ProcessProbe_t *pProbe, const wchar_t *pwszPath ) noexcept;
ProbeModule_t *FindModuleByAddress( const ProcessProbe_t *pProbe, u64 ulAddress ) noexcept;
void InitProbe( ProcessProbe_t *pProbe ) noexcept;
EScanStatus ToolhelpSnapshot( ProcessProbe_t *pProbe, u32 unPid, EProbeFlags eFlags ) noexcept;
void CleanupProbe( ProcessProbe_t *pProbe ) noexcept;

EScanStatus WalkProcess( ProcessProbe_t *pProbe, u32 unPid, EProbeFlags eFlags ) noexcept;

bool WalkProcessRegion( HANDLE hProcess, RegionWalk_t *pWalk ) noexcept;
void ReleaseScanSession( ScanSession_t *pSession ) noexcept;

EProbeFlags *PermuteScanAccessFlags( EProbeFlags *peFlags, EScanAccess eAccess ) noexcept;

} // namespace vac::workers::image_scan
