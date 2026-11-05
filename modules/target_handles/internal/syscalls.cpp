// @binary: 762110ce
#include "internal/types.hpp"
#include "crt/intrinsics.hpp"

namespace vac::workers::target_handles
{

constinit u32 g_unOpenSsn = 0;
constinit u32 g_unQuerySsn = 0;
constinit bool g_bUseX64Gate = false;

namespace
{

#pragma pack( push, 1 )
struct ObjectAttributes64_t
{
	u32 m_cubLength;
	u32 m_unPadding0;
	u64 m_ulRootDirectory;
	u64 m_ulObjectName;
	u32 m_unAttributes;
	u32 m_unPadding1;
	u64 m_ulSecurityDescriptor;
	u64 m_ulSecurityQualityOfService;
};
#pragma pack( pop )
VAC_LAYOUT_SIZE( ObjectAttributes64_t, 48 );

constinit u32 s_unSavedEbx = 0;
constinit u32 s_unSavedEsi = 0;
constinit u32 s_unSavedEdi = 0;
constinit u32 s_unSavedEbp = 0;
constinit u32 s_unSavedEsp = 0;
constinit u64 s_ulSavedR10 = 0;
constinit u32 s_rgunFarEnter[2] = {};
constinit u32 s_rgunFarLeave[2] = {};

} // namespace

// @note / sapdragon: REX prefixed bytes run after the far jump to selector 0x33, the assembler can't write them in 32-bit mode.
// the x64 args are 4 qwords on the caller's stack, r10 is kept in s_ulSavedR10
#define VAC_X64_SYSCALL_BODY()                                                                                         \
	__asm _emit 0x5F                                                                         /* pop rdi */             \
	    __asm _emit 0x4C __asm _emit 0x89 __asm _emit 0x17                                   /* mov [rdi], r10 */      \
	    __asm _emit 0x48 __asm _emit 0x8B __asm _emit 0x4C __asm _emit 0x24 __asm _emit 0x08 /* mov rcx, [rsp+8] */    \
	    __asm _emit 0x48 __asm _emit 0x8B __asm _emit 0x54 __asm _emit 0x24 __asm _emit 0x10 /* mov rdx, [rsp+10h] */  \
	    __asm _emit 0x4C __asm _emit 0x8B __asm _emit 0x44 __asm _emit 0x24 __asm _emit 0x18 /* mov r8, [rsp+18h] */   \
	    __asm _emit 0x4C __asm _emit 0x8B __asm _emit 0x4C __asm _emit 0x24 __asm _emit 0x20 /* mov r9, [rsp+20h] */   \
	    __asm _emit 0x4C __asm _emit 0x8B __asm _emit 0xD1                                   /* mov r10, rcx */        \
	    __asm _emit 0x0F __asm _emit 0x05                                                    /* syscall */             \
	    __asm _emit 0x4C __asm _emit 0x8B __asm _emit 0x17                                   /* mov r10, [rdi] */      \
	    __asm _emit 0x48 __asm _emit 0x33 __asm _emit 0xC9                                   /* xor rcx, rcx */        \
	    __asm _emit 0x8B __asm _emit 0x0C __asm _emit 0x24                                   /* mov ecx, [rsp] */      \
	    __asm _emit 0xFF __asm _emit 0x29                                                    /* jmp far [rcx] */

// @orig: 762110ce:0x100032E8 (no unique signature)
__declspec( naked ) u32 __cdecl NtQuerySystemInformationX64( u64, u64, u64, u64 )
{
	__asm
	    {
		mov s_unSavedEbx, ebx
		mov s_unSavedEsi, esi
		mov s_unSavedEdi, edi
		mov s_unSavedEbp, ebp
		mov s_unSavedEsp, esp
		lea ecx, s_rgunFarLeave
		mov eax, offset leave_x64
		mov [ecx], eax
		mov dword ptr [ecx + 4], 23h
		push ecx
		lea ecx, s_ulSavedR10
		push 0
		push ecx
		lea ecx, s_rgunFarEnter
		mov eax, offset enter_x64
		mov [ecx], eax
		mov word ptr [ecx + 4], 33h
		mov eax, g_unQuerySsn
		jmp fword ptr [ecx]
	enter_x64:
	    }
	VAC_X64_SYSCALL_BODY()
	__asm
	{
	leave_x64:
		mov ebx, s_unSavedEbx
		mov esi, s_unSavedEsi
		mov edi, s_unSavedEdi
		mov ebp, s_unSavedEbp
		mov esp, s_unSavedEsp
		ret
	}
}

// @orig: 762110ce:0x10003392 (no unique signature)
__declspec( naked ) static void QuerySysenterGate()
{
	__asm
	{
		mov edx, esp
		_emit 0Fh
		_emit 34h
		ret
	}
}

// @orig: 762110ce:0x10003385 (no unique signature)
__declspec( naked ) u32 __cdecl NtQuerySystemInformationSysenter( u32, void *, u32, void * )
{
	__asm
	{
		mov eax, g_unQuerySsn
		mov edx, offset QuerySysenterGate
		call edx
		ret
	}
}

// @orig: 762110ce:0x10003397 (no unique signature)
__declspec( naked ) u32 __cdecl NtOpenProcessX64( u64, u64, u64, u64 )
{
	__asm
	    {
		mov s_unSavedEbx, ebx
		mov s_unSavedEsi, esi
		mov s_unSavedEdi, edi
		mov s_unSavedEbp, ebp
		mov s_unSavedEsp, esp
		lea ecx, s_rgunFarLeave
		mov eax, offset leave_x64
		mov [ecx], eax
		mov dword ptr [ecx + 4], 23h
		push ecx
		lea ecx, s_ulSavedR10
		push 0
		push ecx
		lea ecx, s_rgunFarEnter
		mov eax, offset enter_x64
		mov [ecx], eax
		mov word ptr [ecx + 4], 33h
		mov eax, g_unOpenSsn
		jmp fword ptr [ecx]
	enter_x64:
	    }
	VAC_X64_SYSCALL_BODY()
	__asm
	{
	leave_x64:
		mov ebx, s_unSavedEbx
		mov esi, s_unSavedEsi
		mov edi, s_unSavedEdi
		mov ebp, s_unSavedEbp
		mov esp, s_unSavedEsp
		ret
	}
}

// @orig: 762110ce:0x10003441 (no unique signature)
__declspec( naked ) static void OpenSysenterGate()
{
	__asm
	{
		mov edx, esp
		_emit 0Fh
		_emit 34h
		ret
	}
}

// @orig: 762110ce:0x10003434 (no unique signature)
__declspec( naked ) u32 __cdecl NtOpenProcessSysenter( HANDLE *, u32, void *, void * )
{
	__asm
	{
		mov eax, g_unOpenSsn
		mov edx, offset OpenSysenterGate
		call edx
		ret
	}
}

// @orig: 83 EC ? 83 3D
EScanStatus OpenProcessBySyscall( HANDLE *phProcess, u32 unAccess, u32 unPid ) noexcept
{
	if ( !g_unOpenSsn )
		return EScanStatus::NoSyscallNumber;

	if ( g_bUseX64Gate )
	{
		ObjectAttributes64_t attributes;
		memset( &attributes, 0, sizeof( attributes ) );
		attributes.m_cubLength = sizeof( attributes );

		u32 rgunClientId[4];
		memset( rgunClientId, 0, sizeof( rgunClientId ) );
		rgunClientId[0] = unPid;

		// @note / sapdragon: not cleared and written back on failure too, so a failed open leaves stack garbage in the handle
		// and the callers close it. valve bug, keep it
		u64 ulHandle;
		const EScanStatus eStatus = static_cast<EScanStatus>( NtOpenProcessX64(
		    PointerToX64( &ulHandle ), unAccess, PointerToX64( &attributes ), PointerToX64( rgunClientId ) ) );
		*phProcess = reinterpret_cast<HANDLE>( static_cast<uptr>( ulHandle ) );
		return eStatus;
	}

	OBJECT_ATTRIBUTES attributes;
	memset( &attributes, 0, sizeof( attributes ) );
	attributes.Length = sizeof( attributes );

	u32 rgunClientId[2];
	memset( rgunClientId, 0, sizeof( rgunClientId ) );
	rgunClientId[0] = unPid;
	return static_cast<EScanStatus>( NtOpenProcessSysenter( phProcess, unAccess, &attributes, rgunClientId ) );
}

} // namespace vac::workers::target_handles
