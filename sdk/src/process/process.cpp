// @binary: 42878040
#include "process/process.hpp"

namespace vac::process
{

// @orig: 55 8B EC 83 EC ? 83 3D
void EnableSeDebugPrivilege( const SystemImports_t *pImports ) noexcept
{
	if ( !pImports->OpenProcessToken || !pImports->LookupPrivilegeValueA || !pImports->AdjustTokenPrivileges )
		return;

	HANDLE hToken = nullptr;
	if ( !pImports->OpenProcessToken( pImports->GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken ) )
		return;

	LUID luid{};
	if ( pImports->LookupPrivilegeValueA( nullptr, "SeDebugPrivilege", &luid ) )
	{
		TOKEN_PRIVILEGES privileges{};
		privileges.PrivilegeCount = 1;
		privileges.Privileges[0].Luid = luid;
		privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		pImports->AdjustTokenPrivileges( hToken, FALSE, &privileges, sizeof( privileges ), nullptr, nullptr );
	}
	pImports->CloseHandle( hToken );
}

u32 QueryPackedOsVersion( const SystemImports_t *pImports ) noexcept
{
	if ( !pImports->GetVersionExA )
		return 0;

	OSVERSIONINFOEXA version{};
	version.dwOSVersionInfoSize = sizeof( version );
	if ( !pImports->GetVersionExA( &version ) )
		return 0;

	return PackOsVersion( version.dwPlatformId, version.dwMajorVersion, version.dwMinorVersion );
}

} // namespace vac::process
