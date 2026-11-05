// @binary: de9615cb
#include "internal/types.hpp"
#include "bootstrap/blob.hpp"
#include "core/module.hpp"
#include "crt/intrinsics.hpp"
#include "nt/nt.hpp"

namespace vac::workers::timing_check
{

namespace
{

// @note / sapdragon: Valve patches this in place and calls it, so .data has to be executable (see the vcxproj)
constinit Stub_t s_Stub = { 0xB8, 0x99999999, 0xC3 };

using PfnStub_t = u32( __cdecl * )();

// @orig: inlined
u32 SampleTickCount() noexcept
{
	const volatile nt::KUserSharedData_t &shared = nt::GetKUserSharedData();

	u32 unLow;
	i32 nHigh1;
	i32 nHigh2;
	do
	{
		nHigh1 = shared.m_TickCount.m_nHigh1Time;
		unLow = shared.m_TickCount.m_unLowPart;
		nHigh2 = shared.m_TickCount.m_nHigh2Time;
	} while ( nHigh1 != nHigh2 );

	u32 unTicks;
	if ( ( unLow | static_cast<u32>( nHigh2 ) ) != 0 )
		unTicks = shared.m_unTickCountMultiplier * ( static_cast<u32>( nHigh1 ) << 8 ) +
		          static_cast<u32>( ( static_cast<u64>( unLow ) * shared.m_unTickCountMultiplier ) >> 24 );
	else
		unTicks = static_cast<u32>(
		    ( static_cast<u64>( shared.m_unTickCountLowDeprecated ) * shared.m_unTickCountMultiplier ) >> 24 );

	return ( ( unTicks >> 7 ) + 0xFF ) & 0x03FFFF00;
}

} // namespace

// @orig: 55 8B EC 51 53
int RunTimingCheck( const Input_t &input, Report_t &report, u32 *pcubOutput ) noexcept
{
	memset( &report, 0, sizeof( Report_t ) );
	*pcubOutput = sizeof( Report_t );
	report.m_unMagic = k_unReportMagic;

	report.m_unTimingCheck ^= SampleTickCount();
	report.m_unBeingDebugged = NtCurrentTeb()->ProcessEnvironmentBlock->BeingDebugged;

	s_Stub.m_unImmediate = input.m_unStubValue;
	report.m_unTimingCheck ^= reinterpret_cast<PfnStub_t>( &s_Stub )();
	report.m_unTimingCheck ^= SampleTickCount();
	return 0;
}

} // namespace vac::workers::timing_check

#include "internal/module_data.inl"

VAC_WORKER( vac::workers::timing_check::RunTimingCheck, vac::workers::timing_check::k_unModuleId, 1, 0x32, 0xAA, 0x46,
            0x8A, 0x3F, 0xDF, 0xEF, 0xE6, 0x75, 0x22, 0xA4, 0x14, 0x6F, 0x9A, 0xF4, 0x61, 0x11, 0x25, 0x98, 0xD9, 0x33,
            0x71, 0x28, 0xC7, 0xEB, 0xAA, 0x63, 0x06, 0x9B, 0x4D, 0x87, 0xD0 );
