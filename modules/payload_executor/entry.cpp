// @binary: 60e41c53
#include "internal/types.hpp"
#include "bootstrap/blob.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/module.hpp"
#include "crypto/hash/crc32.hpp"
#include "crt/intrinsics.hpp"

namespace vac::workers::payload_executor
{
// @orig: 51 8B 44 24
int RunPayloadExecutor( Input_t &input, Report_t &report, u32 *pcubOutput ) noexcept
{
	if ( *pcubOutput < 0xFD0 )
		return 4;
	*pcubOutput = k_cubReport;
	// @note / sapdragon: the second memset is valve's, it does nothing but it stays
	memset( &report, 0, k_cubReport );
	memset( &report, 0, 0xFD0 );
	if ( !bootstrap::BootstrapMain( &input ) )
	{
		report.m_eStatus = EScanStatus::BootstrapFailed;
		return 0;
	}
	const auto *pImports = g_pImports;
	u8 *pubData = nullptr;
	if ( HasFlag( input.m_eFlags, EPayloadFlags::Allocate ) )
	{
		pubData =
		    static_cast<u8 *>( pImports->VirtualAlloc( nullptr, input.m_cubAllocation, MEM_COMMIT, PAGE_READWRITE ) );
		report.m_unAllocatedMemory = static_cast<u32>( reinterpret_cast<uptr>( pubData ) );
		report.m_eFlags |= EPayloadFlags::Allocate;
		report.m_cubData = input.m_cubAllocation;
	}
	if ( HasFlag( input.m_eFlags, EPayloadFlags::ExistingPointer ) )
	{
		pubData = reinterpret_cast<u8 *>( static_cast<uptr>( input.m_unDataPointer ) );
		report.m_eFlags |= EPayloadFlags::ExistingPointer;
	}
	report.m_unBaseCrc32 = crypto::hash::Crc32_t::Of( k_rgubBase, sizeof( k_rgubBase ) );
	if ( HasFlag( input.m_eFlags, EPayloadFlags::Decrypt ) )
	{
		// @note / sapdragon: capacity really is 0, so any non empty result ends in error 3 and the crc still runs
		// over the required size. the error code then overwrites the bool
		u32 cubPlain = 0, unError = 0;
		report.m_unDecryptResult =
		    DecryptPayload( input.m_rgubPackedBlob, input.m_cubPacked, pubData, &cubPlain, &unError );
		report.m_cubData = cubPlain;
		report.m_unDecryptedCrc32 = crypto::hash::Crc32_t::Of( pubData, cubPlain );
		report.m_eFlags |= EPayloadFlags::Decrypt;
		report.m_unDecryptResult = report.m_unDecryptStatus = unError;
	}
	if ( HasFlag( input.m_eFlags, EPayloadFlags::MakeExecutable ) )
	{
		DWORD unOldProtect = 0;
		pImports->VirtualProtect( pubData, input.m_cubAllocation, PAGE_EXECUTE_READWRITE, &unOldProtect );
		report.m_eFlags |= EPayloadFlags::MakeExecutable;
	}
	if ( HasFlag( input.m_eFlags, EPayloadFlags::Call ) )
	{
		using Entry_t = void( __cdecl * )( ModuleSession_t *, u32 *, Report_t * );
		reinterpret_cast<Entry_t>( pubData + input.m_ibEntry )( g_pSession, &input.m_unDataPointer, &report );
		report.m_eFlags |= EPayloadFlags::Call;
	}
	if ( HasFlag( input.m_eFlags, EPayloadFlags::Free ) )
	{
		// @note / sapdragon: valve really passes MEM_FREE here, not MEM_RELEASE. don't fix it
		::VirtualFree( pubData, input.m_cubAllocation, MEM_FREE );
		report.m_eFlags |= EPayloadFlags::Free;
	}
	bootstrap::BootstrapTeardown();
	return 0;
}
} // namespace vac::workers::payload_executor

#include "internal/module_data.inl"

VAC_WORKER( vac::workers::payload_executor::RunPayloadExecutor, vac::workers::payload_executor::k_unModuleId, 1, 0xC4,
            0xDA, 0xF0, 0xA4, 0x89, 0x24, 0x9C, 0x0B, 0xA5, 0x20, 0x56, 0x60, 0xC9, 0x28, 0x2D, 0x0A, 0x78, 0x2F, 0xF7,
            0x25, 0xA6, 0x24, 0xBA, 0x36, 0x00, 0x29, 0x26, 0x6F, 0x9B, 0xD2, 0xFC, 0x1B );
