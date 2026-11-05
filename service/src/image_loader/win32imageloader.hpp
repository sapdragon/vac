#pragma once

#include <Windows.h>

#include <cstdint>

struct CWin32ModuleLoader
{
	BOOL m_bModuleLoaded;
	void *m_pBaseAddress;
	PIMAGE_NT_HEADERS32 m_pNTHeaders;
	uint32_t m_uiImportedModulesCount;
	HMODULE *m_ppImportedModules;
};
static_assert( sizeof( CWin32ModuleLoader ) == 0x14, "the original allocates exactly this much" );

class CWin32ImageLoader
{
public:
	static bool ProcessImports( CWin32ModuleLoader *pImage );
	static void ProcessSectionCharacteristics( CWin32ModuleLoader *pImage );
	static void ProcessRelocations( CWin32ModuleLoader *pImage, intptr_t nDelta );
};

CWin32ModuleLoader *LoadModuleHiddenInternal( const void *pvImageBuffer, void *pvPreferredLoadAddress,
                                              bool bShouldCallEntryPoint );
void UnloadModuleHiddenInternal( CWin32ModuleLoader *pImage );
void *GetProcAddressHidden( const CWin32ModuleLoader *pImage, const char *pszName );
