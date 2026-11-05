#pragma once

#include "bootstrap/imports.hpp"
#include "core/layout.hpp"
#include "core/types.hpp"

namespace vac::nt
{

struct Arch32_t
{
	using Pointer_t = u32;

	using PebRest_t = u8[448];
	using LdrEntryRest_t = u8[20];

	static constexpr u32 k_cubPebLdrSnapshot = 36;
	static constexpr u32 k_cubLdrEntrySnapshot = 72;
	static constexpr u32 k_cubProcessParametersSnapshot = 76;
};

struct Arch64_t
{
	using Pointer_t = u64;

	using PebRest_t = u8[280];
	using LdrEntryRest_t = u8[36];

	static constexpr u32 k_cubPebLdrSnapshot = 88;
	static constexpr u32 k_cubLdrEntrySnapshot = 140;
	static constexpr u32 k_cubProcessParametersSnapshot = 132;
};

template <typename Arch_t>
struct UnicodeString_t
{
	u16 m_cubLength;
	u16 m_cubMaximumLength;
	typename Arch_t::Pointer_t m_ulBuffer;
};

template <typename Arch_t>
struct ListEntry_t
{
	typename Arch_t::Pointer_t m_ulFlink;
	typename Arch_t::Pointer_t m_ulBlink;
};

template <typename Arch_t>
struct ProcessBasicInformation_t
{
	i32 m_nExitStatus;
	typename Arch_t::Pointer_t m_ulPebBaseAddress;
	typename Arch_t::Pointer_t m_ulAffinityMask;
	i32 m_nBasePriority;
	typename Arch_t::Pointer_t m_ulUniqueProcessId;
	typename Arch_t::Pointer_t m_ulInheritedFromUniqueProcessId;
};

template <typename Arch_t>
struct Peb_t
{
	u8 m_bInheritedAddressSpace;
	u8 m_bReadImageFileExecOptions;
	u8 m_bBeingDebugged;
	u8 m_unBitField;
	typename Arch_t::Pointer_t m_ulMutant;
	typename Arch_t::Pointer_t m_ulImageBaseAddress;
	typename Arch_t::Pointer_t m_ulLdr;
	typename Arch_t::Pointer_t m_ulProcessParameters;
	typename Arch_t::PebRest_t m_rgubRest;
};

template <typename Arch_t>
struct PebLdrData_t
{
	u32 m_cubLength;
	u8 m_bInitialized;
	typename Arch_t::Pointer_t m_ulSsHandle;
	ListEntry_t<Arch_t> m_InLoadOrderModuleList;
	ListEntry_t<Arch_t> m_InMemoryOrderModuleList;
	ListEntry_t<Arch_t> m_InInitializationOrderModuleList;
	typename Arch_t::Pointer_t m_ulEntryInProgress;
	u8 m_bShutdownInProgress;
	typename Arch_t::Pointer_t m_ulShutdownThreadId;
};

template <typename Arch_t>
struct LdrDataTableEntry_t
{
	ListEntry_t<Arch_t> m_InLoadOrderLinks;
	ListEntry_t<Arch_t> m_InMemoryOrderLinks;
	ListEntry_t<Arch_t> m_InInitializationOrderLinks;
	typename Arch_t::Pointer_t m_ulDllBase;
	typename Arch_t::Pointer_t m_ulEntryPoint;
	u32 m_cubSizeOfImage;
	UnicodeString_t<Arch_t> m_FullDllName;
	UnicodeString_t<Arch_t> m_BaseDllName;
	typename Arch_t::LdrEntryRest_t m_rgubRest;
};

template <typename Arch_t>
struct ProcessParameters_t
{
	u32 m_cubMaximumLength;
	u32 m_cubLength;
	u32 m_unFlags;
	u32 m_unDebugFlags;
	typename Arch_t::Pointer_t m_ulConsoleHandle;
	u32 m_unConsoleFlags;
	typename Arch_t::Pointer_t m_ulStandardInput;
	typename Arch_t::Pointer_t m_ulStandardOutput;
	typename Arch_t::Pointer_t m_ulStandardError;
	UnicodeString_t<Arch_t> m_CurrentDirectoryPath;
	typename Arch_t::Pointer_t m_ulCurrentDirectoryHandle;
	UnicodeString_t<Arch_t> m_DllPath;
	UnicodeString_t<Arch_t> m_ImagePathName;
	UnicodeString_t<Arch_t> m_CommandLine;
};

using UnicodeString32_t = UnicodeString_t<Arch32_t>;
using UnicodeString64_t = UnicodeString_t<Arch64_t>;
using ListEntry32_t = ListEntry_t<Arch32_t>;
using ListEntry64_t = ListEntry_t<Arch64_t>;
using ProcessBasicInformation32_t = ProcessBasicInformation_t<Arch32_t>;
using ProcessBasicInformation64_t = ProcessBasicInformation_t<Arch64_t>;
using Peb32_t = Peb_t<Arch32_t>;
using Peb64_t = Peb_t<Arch64_t>;
using PebLdrData32_t = PebLdrData_t<Arch32_t>;
using PebLdrData64_t = PebLdrData_t<Arch64_t>;
using LdrDataTableEntry32_t = LdrDataTableEntry_t<Arch32_t>;
using LdrDataTableEntry64_t = LdrDataTableEntry_t<Arch64_t>;
using ProcessParameters32_t = ProcessParameters_t<Arch32_t>;
using ProcessParameters64_t = ProcessParameters_t<Arch64_t>;

VAC_LAYOUT_SIZE( UnicodeString32_t, 0x08 );
VAC_LAYOUT_SIZE( UnicodeString64_t, 0x10 );
VAC_LAYOUT( UnicodeString64_t, m_ulBuffer, 0x08 );
VAC_LAYOUT_SIZE( ProcessBasicInformation32_t, 24 );
VAC_LAYOUT( ProcessBasicInformation32_t, m_ulPebBaseAddress, 0x04 );
VAC_LAYOUT( ProcessBasicInformation32_t, m_ulInheritedFromUniqueProcessId, 0x14 );
VAC_LAYOUT_SIZE( ProcessBasicInformation64_t, 48 );
VAC_LAYOUT( ProcessBasicInformation64_t, m_ulPebBaseAddress, 0x08 );
VAC_LAYOUT( ProcessBasicInformation64_t, m_ulInheritedFromUniqueProcessId, 0x28 );

// @note / sapdragon: image_scan's PebFragment32_t shifts these by 4. it is wrong, 33211402 reads Ldr and the
// parameters at the offsets below
VAC_LAYOUT( Peb32_t, m_bBeingDebugged, 0x02 );
VAC_LAYOUT( Peb32_t, m_ulImageBaseAddress, 0x08 );
VAC_LAYOUT( Peb32_t, m_ulLdr, 0x0C );
VAC_LAYOUT( Peb32_t, m_ulProcessParameters, 0x10 );
VAC_LAYOUT_SIZE( Peb32_t, 468 );
VAC_LAYOUT( Peb64_t, m_bBeingDebugged, 0x02 );
VAC_LAYOUT( Peb64_t, m_ulImageBaseAddress, 0x10 );
VAC_LAYOUT( Peb64_t, m_ulLdr, 0x18 );
VAC_LAYOUT( Peb64_t, m_ulProcessParameters, 0x20 );
VAC_LAYOUT_SIZE( Peb64_t, 320 );

VAC_LAYOUT( PebLdrData32_t, m_InLoadOrderModuleList, 0x0C );
VAC_LAYOUT( PebLdrData32_t, m_InMemoryOrderModuleList, 0x14 );
VAC_LAYOUT( PebLdrData32_t, m_InInitializationOrderModuleList, 0x1C );
VAC_LAYOUT( PebLdrData32_t, m_ulEntryInProgress, Arch32_t::k_cubPebLdrSnapshot );
VAC_LAYOUT_SIZE( PebLdrData32_t, 0x30 );
VAC_LAYOUT( PebLdrData64_t, m_InLoadOrderModuleList, 0x10 );
VAC_LAYOUT( PebLdrData64_t, m_InMemoryOrderModuleList, 0x20 );
VAC_LAYOUT( PebLdrData64_t, m_InInitializationOrderModuleList, 0x30 );
VAC_LAYOUT_SIZE( PebLdrData64_t, Arch64_t::k_cubPebLdrSnapshot );

VAC_LAYOUT( LdrDataTableEntry32_t, m_InMemoryOrderLinks, 0x08 );
VAC_LAYOUT( LdrDataTableEntry32_t, m_ulDllBase, 0x18 );
VAC_LAYOUT( LdrDataTableEntry32_t, m_cubSizeOfImage, 0x20 );
VAC_LAYOUT( LdrDataTableEntry32_t, m_FullDllName, 0x24 );
VAC_LAYOUT( LdrDataTableEntry32_t, m_BaseDllName, 0x2C );
VAC_LAYOUT_SIZE( LdrDataTableEntry32_t, Arch32_t::k_cubLdrEntrySnapshot );
VAC_LAYOUT( LdrDataTableEntry64_t, m_InMemoryOrderLinks, 0x10 );
VAC_LAYOUT( LdrDataTableEntry64_t, m_ulDllBase, 0x30 );
VAC_LAYOUT( LdrDataTableEntry64_t, m_cubSizeOfImage, 0x40 );
VAC_LAYOUT( LdrDataTableEntry64_t, m_FullDllName, 0x48 );
VAC_LAYOUT( LdrDataTableEntry64_t, m_BaseDllName, 0x58 );
VAC_LAYOUT( LdrDataTableEntry64_t, m_rgubRest, 0x68 );

VAC_LAYOUT( ProcessParameters32_t, m_CurrentDirectoryPath, 0x24 );
VAC_LAYOUT( ProcessParameters32_t, m_ImagePathName, 0x38 );
VAC_LAYOUT( ProcessParameters32_t, m_CommandLine, 0x40 );
VAC_LAYOUT( ProcessParameters64_t, m_CurrentDirectoryPath, 0x38 );
VAC_LAYOUT( ProcessParameters64_t, m_ImagePathName, 0x60 );
VAC_LAYOUT( ProcessParameters64_t, m_CommandLine, 0x70 );

struct KSystemTime_t
{
	u32 m_unLowPart;
	i32 m_nHigh1Time;
	i32 m_nHigh2Time;
};
VAC_LAYOUT_SIZE( KSystemTime_t, 12 );

struct KUserSharedData_t
{
	u32 m_unTickCountLowDeprecated;
	u32 m_unTickCountMultiplier;
	KSystemTime_t m_InterruptTime;
	KSystemTime_t m_SystemTime;
	u8 m_rgubUnused[0x320 - 0x020];
	KSystemTime_t m_TickCount;
};
VAC_LAYOUT( KUserSharedData_t, m_unTickCountMultiplier, 0x004 );
VAC_LAYOUT( KUserSharedData_t, m_InterruptTime, 0x008 );
VAC_LAYOUT( KUserSharedData_t, m_SystemTime, 0x014 );
VAC_LAYOUT( KUserSharedData_t, m_TickCount, 0x320 );

inline const volatile KUserSharedData_t &GetKUserSharedData() noexcept
{
	return *reinterpret_cast<const volatile KUserSharedData_t *>( 0x7FFE0000u );
}

struct ObjectDirectoryEntry_t
{
	UNICODE_STRING m_Name;
	UNICODE_STRING m_TypeName;
};
VAC_LAYOUT( ObjectDirectoryEntry_t, m_TypeName, sizeof( UNICODE_STRING ) );

} // namespace vac::nt
