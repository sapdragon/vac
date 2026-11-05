#pragma once

#include "bootstrap/imports.hpp"
#include "core/layout.hpp"
#include "core/packets.hpp"
#include "core/scan_status.hpp"

namespace vac::workers::target_handles
{

inline constexpr u32 k_unModuleId = 0x08A9324E;
inline constexpr u32 k_unReportMagic = 0xB6EC1BED;

#pragma pack( push, 1 )
struct Input_t
{
	u8 m_rgubBootstrap[96];
	u32 m_unTargetPid;
	u32 m_unUseX64Gate;
	u32 m_unQuerySsn;
	u32 m_unOpenSsn;
	u8 m_rgubReserved[48];
};

struct HandleTotal_t
{
	u32 m_unPid;
	u32 m_cHandles;
};

struct OwnerRow_t
{
	u32 m_unPid;
	u32 m_unVolumeSerial;
	u32 m_unFileIndexLow;
	u32 m_unFileIndexHigh;
	u32 m_unGrantedAccess;
	EScanStatus m_eStatus;
	char m_rgchNameTail[40];
};

struct Report_t
{
	u8 m_rgubDispatcher[16];
	u32 m_unMagic;
	EScanStatus m_eStatus;
	u32 m_cRows;
	u32 m_cPasses;
	u32 m_cInitialHandles;
	u32 m_unReserved;
	HandleTotal_t m_rgTotals[11];
	OwnerRow_t m_rgRows[62];
};

struct HandleEntry_t
{
	u32 m_unPidAndBackTrace;
	u8 m_unType;
	u8 m_unAttributes;
	u16 m_unHandle;
	u64 m_ulObject;
	u32 m_unGrantedAccess;
	u32 m_unPadding;
};
#pragma pack( pop )
VAC_LAYOUT( Input_t, m_unTargetPid, 0x60 );
VAC_LAYOUT( Input_t, m_unUseX64Gate, 0x64 );
VAC_LAYOUT( Input_t, m_unQuerySsn, 0x68 );
VAC_LAYOUT( Input_t, m_unOpenSsn, 0x6C );
VAC_LAYOUT_SIZE( Input_t, 160 );
VAC_LAYOUT( OwnerRow_t, m_unGrantedAccess, 16 );
VAC_LAYOUT( OwnerRow_t, m_eStatus, 20 );
VAC_LAYOUT( OwnerRow_t, m_rgchNameTail, 24 );
VAC_LAYOUT_SIZE( OwnerRow_t, 64 );
VAC_LAYOUT( Report_t, m_unMagic, 0x10 );
VAC_LAYOUT( Report_t, m_eStatus, 0x14 );
VAC_LAYOUT( Report_t, m_cRows, 0x18 );
VAC_LAYOUT( Report_t, m_cPasses, 0x1C );
VAC_LAYOUT( Report_t, m_cInitialHandles, 0x20 );
VAC_LAYOUT( Report_t, m_rgTotals, 0x28 );
VAC_LAYOUT( Report_t, m_rgRows, 0x80 );
VAC_LAYOUT_SIZE( Report_t, k_cubReport );
VAC_LAYOUT( HandleEntry_t, m_ulObject, 8 );
VAC_LAYOUT( HandleEntry_t, m_unGrantedAccess, 16 );
VAC_LAYOUT_SIZE( HandleEntry_t, 24 );

// @note / sapdragon: valve sign extends every pointer it hands to the 64-bit side
inline u64 PointerToX64( const void *pAddress ) noexcept
{
	return static_cast<u64>( static_cast<i64>( static_cast<i32>( reinterpret_cast<uptr>( pAddress ) ) ) );
}

extern u32 g_unOpenSsn;
extern u32 g_unQuerySsn;
extern bool g_bUseX64Gate;

u32 __cdecl NtOpenProcessX64( u64 ulHandle, u64 ulAccess, u64 ulAttributes, u64 ulClientId );
u32 __cdecl NtOpenProcessSysenter( HANDLE *phProcess, u32 unAccess, void *pAttributes, void *pClientId );
u32 __cdecl NtQuerySystemInformationX64( u64 ulClass, u64 ulBuffer, u64 ulCubBuffer, u64 ulReturned );
u32 __cdecl NtQuerySystemInformationSysenter( u32 unClass, void *pBuffer, u32 cubBuffer, void *pReturned );

EScanStatus OpenProcessBySyscall( HANDLE *phProcess, u32 unAccess, u32 unPid ) noexcept;

EScanStatus WatchTargetHandles( const Input_t &input, Report_t &report, HANDLE *phProcess, u8 **ppubHandles ) noexcept;

} // namespace vac::workers::target_handles
