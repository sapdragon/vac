// @binary: 60e41c53
#pragma once
#include "bootstrap/bootstrap.hpp"
#include "core/enum.hpp"
#include "core/packets.hpp"
#include "core/scan_status.hpp"

namespace vac::workers::payload_executor
{
inline constexpr u32 k_unModuleId = 0x0236ED5F;
enum class EPayloadFlags : u32
{
	Allocate = 2,
	ExistingPointer = 4,
	Decrypt = 8,
	MakeExecutable = 16,
	Call = 32,
	Free = 64
};
VAC_FLAGS( EPayloadFlags );
#pragma pack( push, 1 )
struct Input_t
{
	u8 m_rgubBootstrap[32];
	u32 m_unDataPointer;
	u32 m_ibEntry;
	u32 m_cubAllocation;
	u32 m_cubPacked;
	EPayloadFlags m_eFlags;
	u32 m_rgunReserved[2];
	u8 m_rgubPackedBlob[100];
};
struct Report_t
{
	u8 m_rgubDispatcher[16];
	EScanStatus m_eStatus;
	EPayloadFlags m_eFlags;
	u32 m_unBaseCrc32;
	u32 m_unDecryptedCrc32;
	u32 m_unAllocatedMemory;
	u32 m_cubData;
	u32 m_unDecryptResult;
	u32 m_unDecryptStatus;
	u8 m_rgubReserved[4048];
};
#pragma pack( pop )
VAC_LAYOUT( Input_t, m_unDataPointer, 32 );
VAC_LAYOUT( Input_t, m_ibEntry, 36 );
VAC_LAYOUT( Input_t, m_cubAllocation, 40 );
VAC_LAYOUT( Input_t, m_cubPacked, 44 );
VAC_LAYOUT( Input_t, m_eFlags, 48 );
VAC_LAYOUT( Input_t, m_rgubPackedBlob, 60 );
VAC_LAYOUT( Report_t, m_eStatus, 16 );
VAC_LAYOUT( Report_t, m_eFlags, 20 );
VAC_LAYOUT( Report_t, m_unBaseCrc32, 24 );
VAC_LAYOUT( Report_t, m_unDecryptedCrc32, 28 );
VAC_LAYOUT( Report_t, m_unAllocatedMemory, 32 );
VAC_LAYOUT( Report_t, m_cubData, 36 );
VAC_LAYOUT( Report_t, m_unDecryptResult, 40 );
VAC_LAYOUT( Report_t, m_unDecryptStatus, 44 );
VAC_LAYOUT( Report_t, m_rgubReserved, 48 );
VAC_LAYOUT_SIZE( Input_t, 160 );
VAC_LAYOUT_SIZE( Report_t, k_cubReport );

bool DecryptPayload( const u8 *pubPacked, u32 cubPacked, u8 *pubOutput, u32 *pcubOutput, u32 *punError ) noexcept;
extern const u8 k_rgubBase[0x4000];
} // namespace vac::workers::payload_executor
