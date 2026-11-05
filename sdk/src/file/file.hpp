#pragma once

#include "bootstrap/imports.hpp"
#include "core/types.hpp"

namespace vac::file
{

enum class EOpenByIdStatus : u32
{
	Ok = 0,
	ImportsMissing = 78,
	FindFirstFailed = 91,
	OpenFailed = 92,
	NoVolumeMatched = 93,
};

[[nodiscard]] u32 GetFileSizeOrZero( const SystemImports_t *pImports, HANDLE hFile ) noexcept;

[[nodiscard]] bool GetFileSize32( const SystemImports_t *pImports, HANDLE hFile, u32 *pcubSize ) noexcept;

[[nodiscard]] bool ReadWholeFile( const SystemImports_t *pImports, HANDLE hFile, u8 **ppubData, u32 *pcubData,
                                  bool bAllowLinkedHeap ) noexcept;
void FreeWholeFile( const SystemImports_t *pImports, u8 *pubData, bool bAllowLinkedHeap ) noexcept;

[[nodiscard]] EOpenByIdStatus OpenByVolumeAndId( const SystemImports_t *pImports, u32 unVolumeSerial, u64 ulFileId,
                                                 DWORD unDesiredAccess, HANDLE *phFile, u32 *punLastError ) noexcept;

} // namespace vac::file
