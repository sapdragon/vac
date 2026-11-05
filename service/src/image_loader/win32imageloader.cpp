// @binary: 7ebac2a4
#include "image_loader/win32imageloader.hpp"

#include <cstdlib>
#include <cstring>

namespace
{

constexpr DWORD k_rgunNewProtect[8] = {
    PAGE_NOACCESS, PAGE_WRITECOPY,         PAGE_READONLY,     PAGE_READWRITE,
    PAGE_EXECUTE,  PAGE_EXECUTE_WRITECOPY, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
};

IMAGE_SECTION_HEADER *GetFirstSection( PIMAGE_NT_HEADERS32 pNTHeaders )
{
	return IMAGE_FIRST_SECTION( pNTHeaders );
}

using PfnDllMain_t = BOOL( WINAPI * )( void *pvBase, DWORD unReason, void *pvReserved );

void CallEntryPoint( const CWin32ModuleLoader *pImage, DWORD unReason )
{
	const auto pfnEntryPoint = reinterpret_cast<PfnDllMain_t>(
	    static_cast<char *>( pImage->m_pBaseAddress ) + pImage->m_pNTHeaders->OptionalHeader.AddressOfEntryPoint );
	pfnEntryPoint( pImage->m_pBaseAddress, unReason, nullptr );
}

void FreeImportedModules( CWin32ModuleLoader *pImage )
{
	if ( !pImage->m_ppImportedModules )
		return;

	for ( uint32_t iModule = 0; iModule < pImage->m_uiImportedModulesCount; ++iModule )
	{
		if ( pImage->m_ppImportedModules[iModule] != reinterpret_cast<HMODULE>( -1 ) )
			FreeLibrary( pImage->m_ppImportedModules[iModule] );
	}
	free( pImage->m_ppImportedModules );
}

} // namespace

// @orig: 55 8B EC 83 EC ? 53 56 8B 75 ? 57 8B 7E
bool CWin32ImageLoader::ProcessImports( CWin32ModuleLoader *pImage )
{
	auto *pubBase = static_cast<char *>( pImage->m_pBaseAddress );
	const IMAGE_DATA_DIRECTORY &directory =
	    pImage->m_pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if ( !directory.Size )
		return true;

	auto *pDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>( pubBase + directory.VirtualAddress );
	if ( IsBadReadPtr( pDescriptor, sizeof( IMAGE_IMPORT_DESCRIPTOR ) ) )
		return true;

	do
	{
		if ( !pDescriptor->Name )
			break;

		const HMODULE hModule = LoadLibraryExA( pubBase + pDescriptor->Name, nullptr, 0 );
		if ( !hModule )
			return false;

		auto *ppImportedModules = static_cast<HMODULE *>(
		    realloc( pImage->m_ppImportedModules, sizeof( HMODULE ) * ( pImage->m_uiImportedModulesCount + 1 ) ) );
		pImage->m_ppImportedModules = ppImportedModules;
		if ( !ppImportedModules )
			return false;
		ppImportedModules[pImage->m_uiImportedModulesCount++] = hModule;

		const DWORD ibThunks =
		    pDescriptor->OriginalFirstThunk ? pDescriptor->OriginalFirstThunk : pDescriptor->FirstThunk;
		const auto *pThunk = reinterpret_cast<const IMAGE_THUNK_DATA32 *>( pubBase + ibThunks );
		auto *ppfnImport = reinterpret_cast<FARPROC *>( pubBase + pDescriptor->FirstThunk );
		for ( ; pThunk->u1.AddressOfData; ++pThunk, ++ppfnImport )
		{
			const char *pszName;
			if ( IMAGE_SNAP_BY_ORDINAL32( pThunk->u1.Ordinal ) )
				pszName = MAKEINTRESOURCEA( static_cast<WORD>( pThunk->u1.Ordinal ) );
			else
				pszName = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>( pubBase + pThunk->u1.AddressOfData )->Name;

			*ppfnImport = GetProcAddress( hModule, pszName );
			if ( !*ppfnImport )
				return false;
		}

		++pDescriptor;
	} while ( !IsBadReadPtr( pDescriptor, sizeof( IMAGE_IMPORT_DESCRIPTOR ) ) );

	return true;
}

// @orig: 55 8B EC 83 EC ? 56 57 8B 7D ? 33 C0
void CWin32ImageLoader::ProcessSectionCharacteristics( CWin32ModuleLoader *pImage )
{
	const PIMAGE_NT_HEADERS32 pNTHeaders = pImage->m_pNTHeaders;
	IMAGE_SECTION_HEADER *pSection = GetFirstSection( pNTHeaders );
	for ( WORD iSection = 0; iSection < pNTHeaders->FileHeader.NumberOfSections; ++iSection, ++pSection )
	{
		const DWORD unCharacteristics = pSection->Characteristics;
		void *pvSection = reinterpret_cast<void *>( static_cast<uintptr_t>( pSection->Misc.PhysicalAddress ) );
		if ( unCharacteristics & IMAGE_SCN_MEM_DISCARDABLE )
		{
			VirtualFree( pvSection, pSection->SizeOfRawData, MEM_DECOMMIT );
			continue;
		}

		DWORD unProtect = k_rgunNewProtect[( ( unCharacteristics & IMAGE_SCN_MEM_EXECUTE ) ? 4 : 0 ) +
		                                   ( ( unCharacteristics & IMAGE_SCN_MEM_READ ) ? 2 : 0 ) +
		                                   ( ( unCharacteristics & IMAGE_SCN_MEM_WRITE ) ? 1 : 0 )];
		if ( unCharacteristics & IMAGE_SCN_MEM_NOT_CACHED )
			unProtect |= PAGE_NOCACHE;

		// @note / sapdragon: the original picks a section size for empty raw data and then ignores it, the protect
		// call still gets zero. so these sections just stay read-write
		if ( !pSection->SizeOfRawData )
		{
			DWORD cubSection;
			if ( unCharacteristics & IMAGE_SCN_CNT_INITIALIZED_DATA )
				cubSection = pNTHeaders->OptionalHeader.SizeOfInitializedData;
			else if ( unCharacteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA )
				cubSection = pNTHeaders->OptionalHeader.SizeOfUninitializedData;
			else
				continue;

			if ( !cubSection )
				continue;
		}

		DWORD unOldProtect;
		VirtualProtect( pvSection, pSection->SizeOfRawData, unProtect, &unOldProtect );
	}
}

// @orig: 55 8B EC 8B 45 ? 57 8B 78
void CWin32ImageLoader::ProcessRelocations( CWin32ModuleLoader *pImage, intptr_t nDelta )
{
	const IMAGE_DATA_DIRECTORY &directory =
	    pImage->m_pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if ( !directory.Size )
		return;

	auto *pubBase = static_cast<char *>( pImage->m_pBaseAddress );
	auto *pBlock = reinterpret_cast<IMAGE_BASE_RELOCATION *>( pubBase + directory.VirtualAddress );
	while ( pBlock->VirtualAddress )
	{
		char *pubPage = pubBase + pBlock->VirtualAddress;
		const auto *punEntries = reinterpret_cast<const WORD *>( pBlock + 1 );
		const DWORD cEntries = ( pBlock->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) >> 1;
		for ( DWORD iEntry = 0; iEntry < cEntries; ++iEntry )
		{
			const WORD unEntry = punEntries[iEntry];
			if ( ( unEntry & 0xF000 ) == ( IMAGE_REL_BASED_HIGHLOW << 12 ) )
				*reinterpret_cast<intptr_t *>( pubPage + ( unEntry & 0xFFF ) ) += nDelta;
		}
		pBlock = reinterpret_cast<IMAGE_BASE_RELOCATION *>( reinterpret_cast<char *>( pBlock ) + pBlock->SizeOfBlock );
	}
}

// @orig: 55 8B EC 8B 45 ? 83 EC ? B9
CWin32ModuleLoader *LoadModuleHiddenInternal( const void *pvImageBuffer, void *pvPreferredLoadAddress,
                                              bool bShouldCallEntryPoint )
{
	const auto *pubImage = static_cast<const char *>( pvImageBuffer );
	const auto *pDosHeader = static_cast<const IMAGE_DOS_HEADER *>( pvImageBuffer );
	if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
		return nullptr;

	const auto *pSourceHeaders = reinterpret_cast<const IMAGE_NT_HEADERS32 *>( pubImage + pDosHeader->e_lfanew );
	if ( pSourceHeaders->Signature != IMAGE_NT_SIGNATURE )
		return nullptr;

	const DWORD cubImage = pSourceHeaders->OptionalHeader.SizeOfImage;
	void *pvWantedBase = pvPreferredLoadAddress;
	if ( !pvWantedBase )
		pvWantedBase = reinterpret_cast<void *>( static_cast<uintptr_t>( pSourceHeaders->OptionalHeader.ImageBase ) );

	void *pvReserved = VirtualAlloc( pvWantedBase, cubImage, MEM_RESERVE, PAGE_READWRITE );
	if ( !pvReserved )
	{
		pvReserved = VirtualAlloc( nullptr, cubImage, MEM_RESERVE, PAGE_READWRITE );
		if ( !pvReserved )
			return nullptr;
	}

	auto *pImage = static_cast<CWin32ModuleLoader *>( HeapAlloc( GetProcessHeap(), 0, sizeof( CWin32ModuleLoader ) ) );
	pImage->m_bModuleLoaded = FALSE;
	pImage->m_pNTHeaders = nullptr;
	pImage->m_uiImportedModulesCount = 0;
	pImage->m_ppImportedModules = nullptr;
	pImage->m_pBaseAddress = pvReserved;

	auto *pubBase = static_cast<char *>( VirtualAlloc( pvReserved, cubImage, MEM_COMMIT, PAGE_READWRITE ) );
	// @note / sapdragon: SizeOfHeaders already counts from the file start, so this copies e_lfanew too many bytes.
	// harmless on a real module, the first section sits a page later
	memcpy( pubBase, pvImageBuffer, pDosHeader->e_lfanew + pSourceHeaders->OptionalHeader.SizeOfHeaders );

	pImage->m_pNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS32>( pubBase + pDosHeader->e_lfanew );
	pImage->m_pNTHeaders->OptionalHeader.ImageBase = static_cast<DWORD>( reinterpret_cast<uintptr_t>( pubBase ) );

	IMAGE_SECTION_HEADER *pSection = GetFirstSection( pImage->m_pNTHeaders );
	for ( WORD iSection = 0; iSection < pImage->m_pNTHeaders->FileHeader.NumberOfSections; ++iSection, ++pSection )
	{
		if ( !pSection->SizeOfRawData )
		{
			const DWORD cubAlignment = pSourceHeaders->OptionalHeader.SectionAlignment;
			if ( cubAlignment > 0 )
			{
				void *pvSection =
				    VirtualAlloc( pubBase + pSection->VirtualAddress, cubAlignment, MEM_COMMIT, PAGE_READWRITE );
				pSection->Misc.PhysicalAddress = static_cast<DWORD>( reinterpret_cast<uintptr_t>( pvSection ) );
				memset( pvSection, 0, cubAlignment );
			}
			continue;
		}

		void *pvSection =
		    VirtualAlloc( pubBase + pSection->VirtualAddress, pSection->SizeOfRawData, MEM_COMMIT, PAGE_READWRITE );
		memcpy( pvSection, pubImage + pSection->PointerToRawData, pSection->SizeOfRawData );
		pSection->Misc.PhysicalAddress = static_cast<DWORD>( reinterpret_cast<uintptr_t>( pvSection ) );
	}

	const intptr_t nDelta =
	    reinterpret_cast<intptr_t>( pubBase ) - static_cast<intptr_t>( pSourceHeaders->OptionalHeader.ImageBase );
	if ( nDelta )
		CWin32ImageLoader::ProcessRelocations( pImage, nDelta );

	if ( !bShouldCallEntryPoint || CWin32ImageLoader::ProcessImports( pImage ) )
	{
		CWin32ImageLoader::ProcessSectionCharacteristics( pImage );

		const DWORD ibEntryPoint = pImage->m_pNTHeaders->OptionalHeader.AddressOfEntryPoint;
		if ( !ibEntryPoint || !bShouldCallEntryPoint )
			return pImage;

		const auto pfnEntryPoint = reinterpret_cast<PfnDllMain_t>( pubBase + ibEntryPoint );
		if ( pfnEntryPoint( pubBase, DLL_PROCESS_ATTACH, nullptr ) )
		{
			pImage->m_bModuleLoaded = TRUE;
			return pImage;
		}
	}

	if ( pImage->m_bModuleLoaded )
		CallEntryPoint( pImage, DLL_PROCESS_DETACH );

	FreeImportedModules( pImage );
	if ( pImage->m_pBaseAddress )
		VirtualFree( pImage->m_pBaseAddress, 0, MEM_RELEASE );
	HeapFree( GetProcessHeap(), 0, pImage );
	return nullptr;
}

// @orig: 55 8B EC 56 8B 75 ? 85 F6 74 ? 80 3E ? 74 ? 8B 46
void UnloadModuleHiddenInternal( CWin32ModuleLoader *pImage )
{
	if ( !pImage )
		return;

	if ( pImage->m_bModuleLoaded )
		CallEntryPoint( pImage, DLL_PROCESS_DETACH );

	FreeImportedModules( pImage );
	if ( pImage->m_pBaseAddress )
		VirtualFree( pImage->m_pBaseAddress, 0, MEM_RELEASE );
	HeapFree( GetProcessHeap(), 0, pImage );
}

// @orig: 55 8B EC 51 8B 45 ? 53 56 57 8B 70
void *GetProcAddressHidden( const CWin32ModuleLoader *pImage, const char *pszName )
{
	const IMAGE_DATA_DIRECTORY &directory =
	    pImage->m_pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if ( !directory.Size )
		return nullptr;

	auto *pubBase = static_cast<char *>( pImage->m_pBaseAddress );
	const auto *pExports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>( pubBase + directory.VirtualAddress );
	if ( !pExports->NumberOfNames || !pExports->NumberOfFunctions )
		return nullptr;

	const auto *pibNames = reinterpret_cast<const DWORD *>( pubBase + pExports->AddressOfNames );
	const auto *piOrdinals = reinterpret_cast<const WORD *>( pubBase + pExports->AddressOfNameOrdinals );
	DWORD iName = 0;
	while ( _stricmp( pszName, pubBase + pibNames[iName] ) != 0 )
	{
		++iName;
		if ( iName >= pExports->NumberOfNames )
			return nullptr;
	}

	// @note / sapdragon: <= is valve's, one past the table still reads
	const DWORD iFunction = piOrdinals[iName];
	if ( iFunction > pExports->NumberOfFunctions )
		return nullptr;

	const auto *pibFunctions = reinterpret_cast<const DWORD *>( pubBase + pExports->AddressOfFunctions );
	return pubBase + pibFunctions[iFunction];
}
