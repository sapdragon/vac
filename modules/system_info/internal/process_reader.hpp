// @binary: a07ed54b
#pragma once

#include "bootstrap/imports.hpp"
#include "core/layout.hpp"
#include "core/scan_status.hpp"
#include "nt/nt.hpp"
#include "process/capture_flags.hpp"

namespace vac::workers::system_info
{

enum class EReadFlags : u8
{
	Modules = 0x01,
	Parameters = 0x04,
	WalkLoadOrder = 0x40,
	WalkInitOrder = 0x80,
};

#pragma pack( push, 1 )
struct ProcessModuleEntry_t
{
	u32 m_cubSizeOfImage;
	u32 m_unUnused04;
	u64 m_ulDllBase;
	u32 m_iLoadIndex;
	wchar_t m_wszName[256];
	wchar_t m_wszPath[260];
	u32 m_unUnused41C;
};

// @note / sapdragon: valve's copy has more callers, this module only keeps the command line
class CProcessReader
{
public:
	void Release() noexcept;
	[[nodiscard]] EScanStatus ReadProcess( u32 unPid, EReadFlags eReadFlags ) noexcept;

	u8 m_rgubUnused000[556];
	u32 m_unPid;
	HANDLE m_hProcess;
	u32 m_unLastError;
	process::ECaptureFlags m_eFlags;
	u32 m_unUnused23C;
	FILETIME m_CreationTime;
	i32 m_cModules;
	ProcessModuleEntry_t *m_pModules;
	u32 m_unUnused250;
	void *m_pUnused254;
	u32 m_unUnused258;
	void *m_pUnused25C;
	u32 m_unUnused260;
	void *m_pUnused264;
	u8 m_rgubUnused268[20];
	void *m_pUnused27C;
	nt::Peb32_t m_Peb;
	u32 m_unParentPid;
	nt::ProcessParameters32_t m_Parameters;
	u32 m_unParametersRest;
	u8 m_bTargetIsNative64;
	u8 m_bSelfIsWow64;
	wchar_t m_wszCurrentDirectory[500];
	wchar_t m_wszImagePath[500];
	wchar_t m_wszCommandLine[1024];
	u8 m_rgubUnused1476[2];

private:
	[[nodiscard]] EScanStatus ReadProcess64( u32 unPid, EReadFlags eReadFlags ) noexcept;
	[[nodiscard]] bool NextLoaderEntry( u32 ulStop, nt::LdrDataTableEntry32_t *pEntry, EReadFlags eReadFlags ) noexcept;
};
#pragma pack( pop )
VAC_LAYOUT_SIZE( ProcessModuleEntry_t, 1056 );
VAC_LAYOUT( ProcessModuleEntry_t, m_ulDllBase, 8 );
VAC_LAYOUT( ProcessModuleEntry_t, m_iLoadIndex, 16 );
VAC_LAYOUT( ProcessModuleEntry_t, m_wszName, 20 );
VAC_LAYOUT( ProcessModuleEntry_t, m_wszPath, 532 );
VAC_LAYOUT( CProcessReader, m_unPid, 556 );
VAC_LAYOUT( CProcessReader, m_hProcess, 560 );
VAC_LAYOUT( CProcessReader, m_unLastError, 564 );
VAC_LAYOUT( CProcessReader, m_eFlags, 568 );
VAC_LAYOUT( CProcessReader, m_CreationTime, 576 );
VAC_LAYOUT( CProcessReader, m_cModules, 584 );
VAC_LAYOUT( CProcessReader, m_pModules, 588 );
VAC_LAYOUT( CProcessReader, m_unUnused250, 592 );
VAC_LAYOUT( CProcessReader, m_pUnused254, 596 );
VAC_LAYOUT( CProcessReader, m_pUnused25C, 604 );
VAC_LAYOUT( CProcessReader, m_pUnused264, 612 );
VAC_LAYOUT( CProcessReader, m_pUnused27C, 636 );
VAC_LAYOUT( CProcessReader, m_Peb, 640 );
VAC_LAYOUT( CProcessReader, m_unParentPid, 1108 );
VAC_LAYOUT( CProcessReader, m_Parameters, 1112 );
VAC_LAYOUT( CProcessReader, m_bTargetIsNative64, 1188 );
VAC_LAYOUT( CProcessReader, m_bSelfIsWow64, 1189 );
VAC_LAYOUT( CProcessReader, m_wszCurrentDirectory, 1190 );
VAC_LAYOUT( CProcessReader, m_wszImagePath, 2190 );
VAC_LAYOUT( CProcessReader, m_wszCommandLine, 3190 );
VAC_LAYOUT_SIZE( CProcessReader, 5240 );

NTSTATUS __stdcall ReadVirtualMemoryAuto( HANDLE hProcess, u64 ulAddress, void *pBuffer, u64 cubRead,
                                          u64 *pcubRead ) noexcept;

} // namespace vac::workers::system_info
