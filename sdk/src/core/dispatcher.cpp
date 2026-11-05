// @binary: 9b85c913
#include "core/dispatcher.hpp"
#include "core/module.hpp"
#include "crt/intrinsics.hpp"
#include "crypto/hash/crc32.hpp"
#include "crypto/ice/ice.hpp"
#include "crypto/random/park_miller.hpp"
#include "crypto/rsa/rsa.hpp"
#include "util/util.hpp"

#include <Windows.h>
#include <intrin.h>

namespace vac
{

constinit Module_t *g_pModuleListHead = nullptr;

namespace
{

struct SessionKey_t
{
	u32 m_unHeader;
	u32 m_cubReport;
	u32 m_rgunIceKey[2];
	u32 m_unTerminator;
	u32 m_rgunPadding[2];
	u32 m_rgunUnsent[25];
};
VAC_LAYOUT( SessionKey_t, m_rgunUnsent, 28 );
VAC_LAYOUT_SIZE( SessionKey_t, 128 );

constinit u32 s_cubPage = 0;

// @orig: inlined
const Module_t *FindWorkerNode( const VacInputPacket_t *pInput ) noexcept
{
	for ( const Module_t *pNode = g_pModuleListHead; pNode; pNode = pNode->m_pNext )
	{
		// @note / sapdragon: a node without a worker also stops the walk and gets called. same in the original
		if ( !pNode->m_pfnWorker ||
		     ( pNode->m_unId == pInput->m_unModuleId && pNode->m_unVersion == pInput->m_unVersion ) )
		{
			return pNode;
		}
	}
	return nullptr;
}

// @orig: inlined
void SealResponse( const u8 *pubReport, VacOutputPacket_t *pOutput, u32 *pcubOutput ) noexcept
{
	u8 rgubRsaPublicKey[200];
	memcpy( rgubRsaPublicKey, k_rgubRsaPublicKey, k_cubRsaPublicKey );

	const i32 nTicks = static_cast<i32>( __rdtsc() );
	crypto::random::ParkMiller_t prng( static_cast<u32>( nTicks < 0 ? nTicks : -nTicks ) );

	SessionKey_t sessionKey;
	u32 *punSessionKey = reinterpret_cast<u32 *>( &sessionKey );
	for ( u32 iWord = 0; iWord < sizeof( SessionKey_t ) / sizeof( u32 ); ++iWord )
		punSessionKey[iWord] = prng.Next();

	sessionKey.m_unTerminator = 0;
	sessionKey.m_cubReport = *pcubOutput;
	sessionKey.m_unHeader = ( sessionKey.m_unHeader & 0xFFFFFF7Fu ) | 0x40u;

	u32 *punResponse = reinterpret_cast<u32 *>( pOutput );
	for ( u32 iWord = *pcubOutput >> 2; iWord < sizeof( VacOutputPacket_t ) / sizeof( u32 ); ++iWord )
		punResponse[iWord] = prng.Next();

	u32 cubRsaOutput = 0x40;
	crypto::rsa::ERsaError eRsaError = crypto::rsa::ERsaError::Ok;
	const bool bRsaOk = crypto::rsa::EncryptSessionKey(
	    reinterpret_cast<const u8 *>( &sessionKey ), offsetof( SessionKey_t, m_rgunUnsent ), rgubRsaPublicKey,
	    k_cubRsaPublicKey, pOutput->m_rgubRsaSessionKey, &cubRsaOutput, &eRsaError );
	pOutput->m_cubRsaPayload = cubRsaOutput;
	pOutput->m_unRsaStatus = static_cast<u32>( eRsaError ) | ( bRsaOk ? 0 : 0x10000 );

	crypto::ice::EncryptBuffer( reinterpret_cast<const u8 *>( sessionKey.m_rgunIceKey ), pubReport, k_cubReport,
	                            pOutput->m_rgubEncryptedReport );

	for ( u32 iWord = 0; iWord < sizeof( SessionKey_t ) / sizeof( u32 ); ++iWord )
		(void)prng.Next();

	*pcubOutput = sizeof( VacOutputPacket_t );
}

} // namespace

// @orig: 55 8B EC 83 E4 ? 81 EC
EDispatchResult __fastcall RunDispatcher( const VacInputPacket_t *pInput, u32 cubInput, VacOutputPacket_t *pOutput,
                                          u32 *pcubOutput ) noexcept
{
	const u32 cubCapacity = *pcubOutput;
	if ( cubInput < sizeof( VacInputPacket_t ) || cubCapacity < sizeof( VacDispatchStatus_t ) )
		return EDispatchResult::BadArguments;

	*pcubOutput = sizeof( VacDispatchStatus_t );
	memset( pOutput, 0, sizeof( VacDispatchStatus_t ) );

	auto *pStatus = reinterpret_cast<VacDispatchStatus_t *>( pOutput );
	pStatus->m_unError = 0xFFFFFFFFu;
	pStatus->m_unSessionId = pInput->m_unSessionId;
	pStatus->m_eStatus = EDispatchStatus::Ok;

	const Module_t *pNode = FindWorkerNode( pInput );
	if ( !pNode )
	{
		pStatus->m_eStatus = EDispatchStatus::ModuleNotFound;
		return EDispatchResult::Success;
	}

	u8 rgubConfig[k_cubEncryptedConfig];
	crypto::ice::DecryptBuffer( pNode->m_rgubIceKey, pInput->m_rgubEncryptedConfig, k_cubEncryptedConfig, rgubConfig );
	if ( crypto::hash::Crc32_t::Of( rgubConfig, k_cubEncryptedConfig ) != pInput->m_unConfigCrc32 )
	{
		pStatus->m_eStatus = EDispatchStatus::IntegrityFailed;
		return EDispatchResult::Success;
	}

	if ( cubCapacity < k_cubReport )
		return EDispatchResult::BadArguments;

	if ( !s_cubPage )
	{
		SYSTEM_INFO systemInfo;
		GetSystemInfo( &systemInfo );
		s_cubPage = systemInfo.dwPageSize;
	}

	const u32 cubSandbox = s_cubPage * ( ( s_cubPage + sizeof( VacOutputPacket_t ) - 1 ) / s_cubPage + 2 );
	u8 *pubSandbox = static_cast<u8 *>( VirtualAlloc( nullptr, cubSandbox, MEM_COMMIT | MEM_RESERVE,
	                                                  util::MapProtectionFlags( util::EProtectMode::NoAccess ) ) );
	if ( !pubSandbox )
		return EDispatchResult::BadArguments;

	EDispatchResult eResult = EDispatchResult::Success;
	u8 *pubReport = pubSandbox + s_cubPage;
	DWORD unOldProtect;
	if ( VirtualProtect( pubReport, cubSandbox - 2 * s_cubPage,
	                     util::MapProtectionFlags( util::EProtectMode::ReadWrite ), &unOldProtect ) )
	{
		*pcubOutput = k_cubReport;
		const int nWorkerResult = pNode->m_pfnWorker( rgubConfig, pubReport, pcubOutput );

		auto *pHeader = reinterpret_cast<VacReportHeader_t *>( pubReport );
		pHeader->m_unReserved = 0;
		pHeader->m_unWorkerResult = static_cast<u32>( nWorkerResult );
		pHeader->m_unSessionId = pInput->m_unSessionId;

		SealResponse( pubReport, pOutput, pcubOutput );
	}
	else
	{
		eResult = EDispatchResult::BadArguments;
	}

	VirtualFree( pubSandbox, 0, MEM_RELEASE );
	return eResult;
}

} // namespace vac
