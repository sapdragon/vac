#pragma once

#include "core/layout.hpp"
#include "core/types.hpp"

namespace vac
{

inline constexpr u32 k_cubEncryptedConfig = 0xA0;
inline constexpr u32 k_cubReport = 0x1000;

inline constexpr u32 k_cubRsaPublicKey = 94;

// @note / sapdragon: differs between module builds, generated per module
extern const u8 k_rgubRsaPublicKey[k_cubRsaPublicKey];

struct VacInputPacket_t
{
	u32 m_unModuleId;
	u32 m_unVersion;
	u32 m_unConfigCrc32;
	u32 m_unSessionId;
	u8 m_rgubEncryptedConfig[k_cubEncryptedConfig];
};
VAC_LAYOUT( VacInputPacket_t, m_unSessionId, 0x0C );
VAC_LAYOUT( VacInputPacket_t, m_rgubEncryptedConfig, 0x10 );
VAC_LAYOUT_SIZE( VacInputPacket_t, 0xB0 );

// @note / sapdragon: the dispatcher overwrites these after the worker returns
struct VacReportHeader_t
{
	u32 m_unSessionId;
	u32 m_unWorkerResult;
	u32 m_unReserved;
};
VAC_LAYOUT_SIZE( VacReportHeader_t, 0x0C );

struct VacOutputPacket_t
{
	u8 m_rgubEncryptedReport[k_cubReport];
	u32 m_cubRsaPayload;
	u32 m_unRsaStatus;
	u8 m_rgubRsaSessionKey[0x80];
};
VAC_LAYOUT( VacOutputPacket_t, m_cubRsaPayload, 0x1000 );
VAC_LAYOUT( VacOutputPacket_t, m_unRsaStatus, 0x1004 );
VAC_LAYOUT( VacOutputPacket_t, m_rgubRsaSessionKey, 0x1008 );
VAC_LAYOUT_SIZE( VacOutputPacket_t, 0x1088 );

enum class EDispatchStatus : u32
{
	Ok = 1,
	IntegrityFailed = 2,
	ModuleNotFound = 3,
};

struct VacDispatchStatus_t
{
	u32 m_unSessionId;
	EDispatchStatus m_eStatus;
	u32 m_unError;
	u32 m_unReserved;
};
VAC_LAYOUT_SIZE( VacDispatchStatus_t, 0x10 );

} // namespace vac
