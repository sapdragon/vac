#pragma once

#include "bootstrap/bootstrap.hpp"
#include "internal/types.hpp"
#include "nt/nt.hpp"

namespace vac::workers::process_memory_map
{

inline constexpr u32 k_unPageExecuteAny =
    PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

enum class EMemoryInformationClass : DWORD
{
	Basic = 0,
	MappedFilename = 2,
};

struct LdrModule_t
{
	u32 m_cubImage;
	u64 m_ulBase;
	u32 m_unIndex;
	wchar_t m_wszBaseName[256];
	wchar_t m_wszFullPath[MAX_PATH];
};
VAC_LAYOUT( LdrModule_t, m_ulBase, 0x08 );
VAC_LAYOUT( LdrModule_t, m_unIndex, 0x10 );
VAC_LAYOUT( LdrModule_t, m_wszBaseName, 0x14 );
VAC_LAYOUT( LdrModule_t, m_wszFullPath, 0x214 );
VAC_LAYOUT_SIZE( LdrModule_t, 0x420 );

struct ProcessContext_t
{
	u32 m_unPid;
	HANDLE m_hProcess;
	u32 m_unLastError;
	process::ECaptureFlags m_eCaptureFlags;
	u64 m_ulCreateTime;
	i32 m_cModules;
	LdrModule_t *m_pModules;
	nt::Peb32_t m_Peb;
	u32 m_unParentPid;
	bool m_bCross64;
	bool m_bSelfWow64;
};

struct AllocationWalk_t
{
	u64 m_ulPreviousStart;
	u64 m_ulCursor;
	MEMORY_BASIC_INFORMATION64 m_First;
	u64 m_ulFirstCommitted;
	u64 m_ulLastCommitEnd;
	u64 m_ulCommitPrefixEnd;
	u64 m_ulQueryAddress;
	u32 m_unLastError;
	u64 m_cubTotal;
	u32 m_unProtectUnion;
	u32 m_unExecuteProtectUnion;
	u32 m_cRegions;
	u32 m_cCommittedRegions;
	u64 m_cubCommitPrefix;
};
VAC_LAYOUT( AllocationWalk_t, m_First, 0x10 );
VAC_LAYOUT( AllocationWalk_t, m_ulFirstCommitted, 0x40 );
VAC_LAYOUT( AllocationWalk_t, m_ulLastCommitEnd, 0x48 );
VAC_LAYOUT( AllocationWalk_t, m_ulCommitPrefixEnd, 0x50 );
VAC_LAYOUT( AllocationWalk_t, m_ulQueryAddress, 0x58 );
VAC_LAYOUT( AllocationWalk_t, m_unLastError, 0x60 );
VAC_LAYOUT( AllocationWalk_t, m_cubTotal, 0x68 );
VAC_LAYOUT( AllocationWalk_t, m_unProtectUnion, 0x70 );
VAC_LAYOUT( AllocationWalk_t, m_cRegions, 0x78 );
VAC_LAYOUT( AllocationWalk_t, m_cubCommitPrefix, 0x80 );
VAC_LAYOUT_SIZE( AllocationWalk_t, 0x90 );

[[nodiscard]] void *ResizeOrAlloc( void *pMemory, usize cubSize ) noexcept;
void CopyWideFilled( wchar_t *pwszDst, const wchar_t *pwszSrc, u32 cChars ) noexcept;
[[nodiscard]] int CompareNoCase( const wchar_t *pwszA, const wchar_t *pwszB, u32 cMaxChars ) noexcept;

[[nodiscard]] bool IsCross64( const SystemImports_t *pImports, HANDLE hProcess ) noexcept;
NTSTATUS QueryVirtualMemory( const SystemImports_t *pImports, HANDLE hProcess, u64 ulAddress,
                             EMemoryInformationClass eClass, void *pOutput, u32 cubOutput, u64 *pcubReturned ) noexcept;
NTSTATUS ReadVirtualMemory( const SystemImports_t *pImports, HANDLE hProcess, u64 ulAddress, void *pOutput,
                            u32 cubOutput, u64 *pcubRead ) noexcept;
[[nodiscard]] u32 QueryBasicInformation( const SystemImports_t *pImports, HANDLE hProcess, u64 ulAddress,
                                         MEMORY_BASIC_INFORMATION64 *pInformation ) noexcept;
u32 GetMappedFileName( const SystemImports_t *pImports, HANDLE hProcess, u64 ulAddress, wchar_t *pwszName ) noexcept;
bool DevicePathToDosPath( const SystemImports_t *pImports, wchar_t *pwszPath ) noexcept;

[[nodiscard]] EScanStatus OpenProcessAndCaptureLdr( ProcessContext_t &context, u32 unPid,
                                                    const SystemImports_t *pImports,
                                                    const ModuleSession_t *pSession ) noexcept;
void ReleaseProcessContext( ProcessContext_t &context, const SystemImports_t *pImports ) noexcept;

[[nodiscard]] const LdrModule_t *GetLdrModule( const ProcessContext_t &context, i32 iModule ) noexcept;
[[nodiscard]] const LdrModule_t *FindLdrModuleContaining( const ProcessContext_t &context, u64 ulAddress ) noexcept;
[[nodiscard]] const LdrModule_t *FindLdrModuleByPath( const ProcessContext_t &context,
                                                      const wchar_t *pwszPath ) noexcept;

[[nodiscard]] bool WalkAllocation( const SystemImports_t *pImports, HANDLE hProcess, AllocationWalk_t &walk ) noexcept;

} // namespace vac::workers::process_memory_map
