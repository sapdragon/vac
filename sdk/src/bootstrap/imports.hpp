#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WINVER
#define WINVER 0x0601
#endif
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif

// clang-format off
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <DbgHelp.h>
#include <SetupAPI.h>
#include <WinTrust.h>
#include <WinCrypt.h>
#include <IPHlpApi.h>
#include <UserEnv.h>
#include <Security.h>
// clang-format on

#include "core/layout.hpp"
#include "core/types.hpp"

namespace vac
{

struct SystemImports_t
{
#define VAC_IMPORT( szLibrary, ReturnType, Name, Args ) ReturnType( __stdcall *Name ) Args;
#include "bootstrap/imports.inl"
#undef VAC_IMPORT

	DWORD m_rgunUnused[28];
};
VAC_LAYOUT_SIZE( SystemImports_t, 200 * sizeof( void * ) );

} // namespace vac
