#pragma once

#include "bootstrap/imports.hpp"
#include "core/layout.hpp"
#include "core/packets.hpp"
#include "core/scan_status.hpp"

namespace vac::workers::system_info
{

inline constexpr u32 k_unModuleIdPrimary = 0x0F8083A0;
inline constexpr u32 k_unModuleIdSecondary = 0x0C2232C2;
inline constexpr u32 k_unReportMagic = 0xA93E4B10;

#pragma pack( push, 1 )
struct Input_t
{
	u8 m_rgubBootstrap[96];
	u32 m_unTargetPid;
	u32 m_unReportXorKey;
	u8 m_rgubReserved[56];
};

struct FileIdentity_t
{
	u64 m_ulFileId;
	u32 m_unVolumeSerial;
	u32 m_unError;
};

struct VolumeEntry_t
{
	u32 m_unNameHash;
	u32 m_unInfoError;
	u32 m_unFileSystemFlags;
	u32 m_unSerial;
	u32 m_unLabelHash;
	u32 m_unFileSystemHash;
	u16 m_unDriveType;
	u16 m_cchMountPoints;
	u32 m_unMountPointHashOrError;
};

struct Report_t
{
	u8 m_rgubDispatcher[16];
	u32 m_unMagic;
	EScanStatus m_eStatus;
	i32 m_nTimeOfDayStatus;
	i32 m_nCodeIntegrityStatus;
	u64 m_ulSystemTimeStart;
	u64 m_ulSystemTimeEnd;
	u32 m_unTickMsStart;
	u32 m_unTickMsEnd;
	u64 m_ulCurrentTime;
	u64 m_ulBootTime;
	u32 m_unVersion;
	u32 m_unCodeIntegrityOptions;
	u32 m_unProcessorArchitecture;
	u32 m_unProcessorType;
	i32 m_nDeviceStatus;
	i32 m_nKernelDebuggerStatus;
	i32 m_nBootEnvironmentStatus;
	i32 m_nRangeStartStatus;
	u32 m_cDisks;
	u16 m_unKernelDebugger;
	u16 m_unUnused06E;
	u8 m_rgubBootIdentifier[16];
	i64 m_lRangeStart;
	u32 m_unPid;
	u32 m_unTid;
	EScanStatus m_eImageNameStatus;
	char m_rgchImageNameTail[36];
	EScanStatus m_eNtdllStatus;
	u32 m_unNtdllTimeDateStamp;
	u32 m_unSsnNtReadVirtualMemory;
	u32 m_unSsnNtQueryVirtualMemory;
	u32 m_unSsnNtOpenProcess;
	u32 m_unSsnNtQuerySystemInformation;
	char m_szWindowsDirectory[200];
	FileIdentity_t m_WindowsDirectory;
	char m_szSystemDirectory[200];
	FileIdentity_t m_SystemDirectory;
	u8 m_rgubUnused280[80];
	u32 m_cLoadedLibraries;
	u32 m_cResolvedImports;
	u32 m_rghLoadedLibraries[16];
	u8 m_rgubImports[640];
	u32 m_unCallerBase;
	u32 m_unCallerDword0;
	u32 m_unCallerDword114;
	u32 m_unCallerDword400;
	u32 m_unUnused5A8;
	u32 m_cVolumes;
	VolumeEntry_t m_rgVolumes[10];
	u32 m_unTargetPid;
	u32 m_hTargetProcess;
	u32 m_unTargetOpenError;
	u32 m_unTargetProcessId;
	u8 m_rgubUnused700[256];
	char m_szTargetCommandLine[1024];
};
#pragma pack( pop )
VAC_LAYOUT( Input_t, m_unTargetPid, 0x60 );
VAC_LAYOUT( Input_t, m_unReportXorKey, 0x64 );
VAC_LAYOUT_SIZE( Input_t, 0xA0 );
VAC_LAYOUT_SIZE( FileIdentity_t, 16 );
VAC_LAYOUT_SIZE( VolumeEntry_t, 32 );
VAC_LAYOUT( Report_t, m_unMagic, 0x10 );
VAC_LAYOUT( Report_t, m_eStatus, 0x14 );
VAC_LAYOUT( Report_t, m_nTimeOfDayStatus, 0x18 );
VAC_LAYOUT( Report_t, m_ulSystemTimeStart, 0x20 );
VAC_LAYOUT( Report_t, m_ulSystemTimeEnd, 0x28 );
VAC_LAYOUT( Report_t, m_unTickMsStart, 0x30 );
VAC_LAYOUT( Report_t, m_unTickMsEnd, 0x34 );
VAC_LAYOUT( Report_t, m_ulCurrentTime, 0x38 );
VAC_LAYOUT( Report_t, m_ulBootTime, 0x40 );
VAC_LAYOUT( Report_t, m_unVersion, 0x48 );
VAC_LAYOUT( Report_t, m_nDeviceStatus, 0x58 );
VAC_LAYOUT( Report_t, m_cDisks, 0x68 );
VAC_LAYOUT( Report_t, m_rgubBootIdentifier, 0x70 );
VAC_LAYOUT( Report_t, m_lRangeStart, 0x80 );
VAC_LAYOUT( Report_t, m_unPid, 0x88 );
VAC_LAYOUT( Report_t, m_rgchImageNameTail, 0x94 );
VAC_LAYOUT( Report_t, m_eNtdllStatus, 0xB8 );
VAC_LAYOUT( Report_t, m_unSsnNtReadVirtualMemory, 0xC0 );
VAC_LAYOUT( Report_t, m_szWindowsDirectory, 0xD0 );
VAC_LAYOUT( Report_t, m_WindowsDirectory, 0x198 );
VAC_LAYOUT( Report_t, m_szSystemDirectory, 0x1A8 );
VAC_LAYOUT( Report_t, m_SystemDirectory, 0x270 );
VAC_LAYOUT( Report_t, m_cLoadedLibraries, 0x2D0 );
VAC_LAYOUT( Report_t, m_rghLoadedLibraries, 0x2D8 );
VAC_LAYOUT( Report_t, m_rgubImports, 0x318 );
VAC_LAYOUT( Report_t, m_unCallerBase, 0x598 );
VAC_LAYOUT( Report_t, m_cVolumes, 0x5AC );
VAC_LAYOUT( Report_t, m_rgVolumes, 0x5B0 );
VAC_LAYOUT( Report_t, m_unTargetPid, 0x6F0 );
VAC_LAYOUT( Report_t, m_hTargetProcess, 0x6F4 );
VAC_LAYOUT( Report_t, m_szTargetCommandLine, 0x800 );
VAC_LAYOUT_SIZE( Report_t, 3072 );

[[nodiscard]] u32 CollectVolumes( VolumeEntry_t *pEntries, const SystemImports_t *pImports ) noexcept;
[[nodiscard]] bool QueryFileIdentity( const wchar_t *pwszPath, u32 *punVolumeSerial, u64 *pulFileId,
                                      const SystemImports_t *pImports ) noexcept;

} // namespace vac::workers::system_info
