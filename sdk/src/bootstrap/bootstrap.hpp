#pragma once

#include "bootstrap/imports.hpp"
#include "core/layout.hpp"
#include "core/types.hpp"

namespace vac
{

#pragma pack( push, 1 )
struct ModuleSession_t
{
	u32 m_unPid;
	u32 m_unTid;
	SYSTEM_INFO m_SystemInfo;
	OSVERSIONINFOEXA m_OsVersion;
	u32 m_unPackedVersion;
	u32 m_unLastError;
	u8 m_rgubUnused0[2];
	wchar_t m_wszSystemDirectory[260];
	wchar_t m_wszWindowsDirectory[260];
	u8 m_rgubUnused1[2];
	HMODULE m_hNtdll;
};
#pragma pack( pop )
VAC_LAYOUT( ModuleSession_t, m_SystemInfo, 0x08 );
VAC_LAYOUT( ModuleSession_t, m_OsVersion, 0x2C );
VAC_LAYOUT( ModuleSession_t, m_unPackedVersion, 200 );
VAC_LAYOUT( ModuleSession_t, m_unLastError, 204 );
VAC_LAYOUT( ModuleSession_t, m_wszSystemDirectory, 210 );
VAC_LAYOUT( ModuleSession_t, m_wszWindowsDirectory, 730 );
VAC_LAYOUT( ModuleSession_t, m_hNtdll, 0x4E4 );
VAC_LAYOUT_SIZE( ModuleSession_t, 1256 );

extern SystemImports_t *const g_pImports;
extern ModuleSession_t *const g_pSession;
extern u32 g_unIntegrityHash;

} // namespace vac

namespace vac::bootstrap
{

[[nodiscard]] bool BootstrapMain( const void *pubInput ) noexcept;

void BootstrapTeardown() noexcept;

} // namespace vac::bootstrap
