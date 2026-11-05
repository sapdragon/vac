// @binary: a07ed54b
#include "bootstrap/blob.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/layout.hpp"
#include "core/module.hpp"
#include "core/packets.hpp"
#include "core/scan_status.hpp"
#include "crt/intrinsics.hpp"

namespace vac::workers::example
{

inline constexpr u32 k_unModuleId = 0x0F8083A0;
inline constexpr u32 k_unReportMagic = 0xABCDEF01;

#pragma pack( push, 1 )
struct Input_t
{
	u8 m_rgubBootstrap[0x60];
	u32 m_unTargetPid;
	u8 m_rgubReserved[0x3C];
};

struct Report_t
{
	u8 m_rgubDispatcher[16];
	u32 m_unMagic;
	EScanStatus m_eStatus;
	u32 m_unTargetPid;
	u32 m_cubPage;
};
#pragma pack( pop )
VAC_LAYOUT( Input_t, m_unTargetPid, 0x60 );
VAC_LAYOUT_SIZE( Input_t, k_cubEncryptedConfig );
VAC_LAYOUT( Report_t, m_unMagic, 0x10 );

int RunExample( const Input_t &input, Report_t &report, u32 *pcubOutput ) noexcept
{
	memset( &report, 0, sizeof( report ) );
	*pcubOutput = sizeof( report );
	report.m_unMagic = k_unReportMagic;

	if ( !bootstrap::BootstrapMain( &input ) )
	{
		report.m_eStatus = EScanStatus::BootstrapFailed;
		return 0;
	}

	report.m_unTargetPid = input.m_unTargetPid;
	report.m_cubPage = g_pSession->m_SystemInfo.dwPageSize;

	char szMessage[64];
	wsprintfA( szMessage, "pid %u, page size %u", report.m_unTargetPid, report.m_cubPage );
	MessageBoxA( nullptr, szMessage, "vac example", MB_OK | MB_ICONINFORMATION );

	bootstrap::BootstrapTeardown();
	return 0;
}

} // namespace vac::workers::example

#include "module_data.inl"

VAC_WORKER( vac::workers::example::RunExample, vac::workers::example::k_unModuleId, 1, 0x7F, 0x02, 0x99, 0xF9, 0x84,
            0x08, 0xE7, 0xB4, 0x25, 0xB1, 0x78, 0x41, 0xC7, 0x20, 0x27, 0xAE, 0x34, 0xEA, 0x5B, 0xB3, 0xF6, 0xA2, 0xC1,
            0xF0, 0x73, 0xC6, 0x2A, 0xB2, 0xE5, 0x6A, 0x3B, 0xD7 );
