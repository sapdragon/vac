#pragma once

#include "bootstrap/imports.hpp"
#include "core/types.hpp"

namespace vac::process
{

void EnableSeDebugPrivilege( const SystemImports_t *pImports ) noexcept;

// @orig: inlined in CollectSystemInfo
constexpr u32 PackOsVersion( u32 unPlatformId, u32 unMajorVersion, u32 unMinorVersion ) noexcept
{
	return unPlatformId | ( unMajorVersion << 8 ) | ( unMinorVersion << 16 );
}

// @note / sapdragon: no original calls GetVersionExA after bootstrap, they read g_pSession->m_unPackedVersion.
// this is for system_handles's rebuild until it migrates
[[nodiscard]] u32 QueryPackedOsVersion( const SystemImports_t *pImports ) noexcept;

template <typename Visitor_t>
bool ForEachSnapshotProcess( const SystemImports_t *pImports, Visitor_t &&visitor ) noexcept
{
	if ( !pImports->CreateToolhelp32Snapshot || !pImports->Process32FirstW || !pImports->Process32NextW ||
	     !pImports->CloseHandle )
		return false;

	HANDLE hSnapshot = pImports->CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if ( hSnapshot == INVALID_HANDLE_VALUE )
		return false;

	PROCESSENTRY32W entry{};
	entry.dwSize = sizeof( entry );
	if ( pImports->Process32FirstW( hSnapshot, &entry ) )
	{
		do
		{
			if ( !visitor( static_cast<const PROCESSENTRY32W &>( entry ) ) )
				break;
		} while ( pImports->Process32NextW( hSnapshot, &entry ) );
	}

	pImports->CloseHandle( hSnapshot );
	return true;
}

} // namespace vac::process
