// @binary: 33211402
#include "../scanner.hpp"
#include "bootstrap/bootstrap.hpp"
#include "crt/intrinsics.hpp"
#include "util/encoding.hpp"
#include "util/strings.hpp"

namespace vac::workers::image_scan
{

namespace
{

constexpr u32 k_cubWindowHalf = sizeof( ScannerContext_t::m_rgubWindow ) / 2;

bool IsSelfMemory( const ScannerContext_t *pCtx ) noexcept
{
	return !pCtx->m_hProcess || pCtx->m_hProcess == INVALID_HANDLE_VALUE;
}

} // namespace

// @orig: 56 8B F1 8B 86
void CloseReader( ScannerContext_t *pCtx ) noexcept
{
	if ( pCtx->m_hFile != INVALID_HANDLE_VALUE )
	{
		g_pImports->CloseHandle( pCtx->m_hFile );
		pCtx->m_hFile = INVALID_HANDLE_VALUE;
	}
	pCtx->m_cubWindow = 0;
	pCtx->m_ulWindowBase = 0;
	pCtx->m_ibWindow = 0;
	pCtx->m_ulClampStart = 0;
	pCtx->m_ulClampEnd = 0;
	pCtx->m_hProcess = nullptr;
}

// @orig: 8B 81 ? ? ? ? 0B 81 ? ? ? ? 74 ? 8B 81
void SetReaderClamp( ScannerContext_t *pCtx, u64 ulStart, u64 ulEnd ) noexcept
{
	if ( pCtx->m_ulMappedBase && IsSelfMemory( pCtx ) )
	{
		pCtx->m_ulClampStart = ulStart;
		pCtx->m_ulClampEnd = ulEnd;
	}
}

// @note / sapdragon: really GENERIC_READ with read sharing here, unlike the opens by id. the original differs per call
// @orig: 81 EC ? ? ? ? 53 55 56 57 8B F1
bool OpenFilePath( ScannerContext_t *pCtx, const wchar_t *pwszPath ) noexcept
{
	CloseReader( pCtx );

	pCtx->m_hFile = g_pImports->CreateFileW( pwszPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
	                                         FILE_ATTRIBUTE_NORMAL, nullptr );

	wchar_t wszResolved[MAX_PATH];
	if ( pCtx->m_hFile == INVALID_HANDLE_VALUE && ResolveSpecialPath( pwszPath, wszResolved ) )
	{
		pCtx->m_hFile = g_pImports->CreateFileW( wszResolved, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		                                         FILE_ATTRIBUTE_NORMAL, nullptr );
	}

	util::encoding::WideToUtf8Bounded( g_pImports, pwszPath, pCtx->m_szPath, sizeof( pCtx->m_szPath ) - 1 );
	return pCtx->m_hFile != INVALID_HANDLE_VALUE;
}

// @orig: 56 8B F1 E8
bool AttachFileHandle( ScannerContext_t *pCtx, HANDLE hFile ) noexcept
{
	CloseReader( pCtx );
	pCtx->m_hFile = hFile;
	util::CopyA( pCtx->m_szPath, "", sizeof( pCtx->m_szPath ) - 1 );
	return pCtx->m_hFile != INVALID_HANDLE_VALUE;
}

// @orig: 51 51 53 55 8B 6C 24
const u8 *ReaderWindow( ScannerContext_t *pCtx, u32 cub ) noexcept
{
	if ( cub > k_cubWindowHalf )
		return nullptr;

	if ( pCtx->m_ibWindow + cub >= pCtx->m_cubWindow )
	{
		u32 ibFill = 0;
		u32 cubFill;
		bool bFill = true;
		if ( pCtx->m_ibWindow + cub == pCtx->m_cubWindow )
		{
			if ( pCtx->m_cubWindow == sizeof( pCtx->m_rgubWindow ) )
			{
				memcpy( pCtx->m_rgubWindow, pCtx->m_rgubWindow + k_cubWindowHalf, k_cubWindowHalf );
				pCtx->m_ulWindowBase += k_cubWindowHalf;
				ibFill = k_cubWindowHalf;
				pCtx->m_ibWindow -= k_cubWindowHalf;
			}
			cubFill = ibFill;
			bFill = ibFill != 0;
		}
		else if ( pCtx->m_cubWindow )
		{
			if ( pCtx->m_cubWindow < sizeof( pCtx->m_rgubWindow ) )
				return nullptr;
			memcpy( pCtx->m_rgubWindow, pCtx->m_rgubWindow + k_cubWindowHalf, k_cubWindowHalf );
			pCtx->m_ulWindowBase += k_cubWindowHalf;
			ibFill = k_cubWindowHalf;
			cubFill = k_cubWindowHalf;
			pCtx->m_ibWindow -= k_cubWindowHalf;
		}
		else
		{
			cubFill = sizeof( pCtx->m_rgubWindow );
		}

		if ( bFill )
		{
			u64 cubRead = 0;
			u8 *pubFill = pCtx->m_rgubWindow + ibFill;
			if ( pCtx->m_hFile == INVALID_HANDLE_VALUE )
			{
				if ( IsSelfMemory( pCtx ) )
				{
					const u32 unFill = static_cast<u32>( pCtx->m_ulWindowBase ) + ibFill;
					if ( pCtx->m_ulClampEnd || pCtx->m_ulClampStart )
					{
						if ( static_cast<u64>( unFill ) >= pCtx->m_ulClampStart )
						{
							if ( static_cast<u64>( unFill ) + cubFill > pCtx->m_ulClampEnd )
								cubFill = static_cast<u32>( pCtx->m_ulClampEnd ) - unFill;
						}
						else
						{
							cubFill = 0;
						}
					}
					memcpy( pubFill,
					        reinterpret_cast<const void *>(
					            static_cast<uptr>( pCtx->m_ulWindowBase + pCtx->m_ulMappedBase + ibFill ) ),
					        cubFill );
					cubRead = cubFill;
				}
				else
				{
					const u64 ulAddress = pCtx->m_ulWindowBase + pCtx->m_ulMappedBase + ibFill;
					ReadTargetMemory( pCtx->m_hProcess, ulAddress, pubFill, cubFill, &cubRead );
					if ( !cubRead && cubFill > k_cubWindowHalf )
					{
						ReadTargetMemory( pCtx->m_hProcess, ulAddress, pubFill, k_cubWindowHalf, &cubRead );
						if ( !cubRead )
							return nullptr;
					}
				}
			}
			else
			{
				DWORD cubFileRead = 0;
				g_pImports->ReadFile( pCtx->m_hFile, pubFill, cubFill, &cubFileRead, nullptr );
				cubRead = cubFileRead;
			}
			pCtx->m_cubWindow = static_cast<u32>( cubRead ) + ibFill;
		}

		if ( pCtx->m_ibWindow + cub > pCtx->m_cubWindow )
			return nullptr;
	}

	const u8 *pubResult = pCtx->m_rgubWindow + pCtx->m_ibWindow;
	pCtx->m_ibWindow += cub;
	return pubResult;
}

// @orig: 51 51 55 56 33 F6
bool ReaderReadBytes( ScannerContext_t *pCtx, void *pvDst, u32 cub ) noexcept
{
	u32 cubDone = 0;
	while ( cubDone != cub )
	{
		u32 cubChunk = cub - cubDone;
		if ( cubChunk > k_cubWindowHalf )
			cubChunk = k_cubWindowHalf;
		const u8 *pubWindow = ReaderWindow( pCtx, cubChunk );
		if ( !pubWindow )
			return false;
		memcpy( static_cast<u8 *>( pvDst ) + cubDone, pubWindow, cubChunk );
		cubDone += cubChunk;
	}
	return true;
}

// @orig: 55 8B EC 83 EC ? 56 57
bool ReaderSeek( ScannerContext_t *pCtx, u32 ibOffset, bool bForce ) noexcept
{
	if ( !bForce )
	{
		if ( pCtx->m_ulWindowBase + pCtx->m_ibWindow == ibOffset )
			return true;
		if ( ibOffset >= pCtx->m_ulWindowBase && ibOffset < pCtx->m_ulWindowBase + pCtx->m_cubWindow )
		{
			pCtx->m_ibWindow = ibOffset - static_cast<u32>( pCtx->m_ulWindowBase );
			return true;
		}
	}

	pCtx->m_ibWindow = ibOffset % k_cubWindowHalf;
	pCtx->m_ulWindowBase = ibOffset - pCtx->m_ibWindow;
	pCtx->m_cubWindow = 0;
	if ( pCtx->m_hFile != INVALID_HANDLE_VALUE &&
	     g_pImports->SetFilePointer( pCtx->m_hFile, static_cast<LONG>( pCtx->m_ulWindowBase ), nullptr, FILE_BEGIN ) !=
	         static_cast<u32>( pCtx->m_ulWindowBase ) )
	{
		CloseReader( pCtx );
		return false;
	}
	return true;
}

// @orig: 55 8B EC 83 EC ? 89 4D
u32 ReaderReadAt( ScannerContext_t *pCtx, u32 ibOffset, void *pvDst, u32 cub ) noexcept
{
	u64 cubRead;
	if ( pCtx->m_hFile == INVALID_HANDLE_VALUE )
	{
		if ( IsSelfMemory( pCtx ) )
		{
			memcpy( pvDst, reinterpret_cast<const void *>( static_cast<uptr>( pCtx->m_ulMappedBase ) + ibOffset ),
			        cub );
			cubRead = cub;
		}
		else
		{
			ReadTargetMemory( pCtx->m_hProcess, pCtx->m_ulMappedBase + ibOffset, pvDst, cub, &cubRead );
		}
	}
	else
	{
		DWORD cubFileRead;
		g_pImports->SetFilePointer( pCtx->m_hFile, static_cast<LONG>( ibOffset ), nullptr, FILE_BEGIN );
		g_pImports->ReadFile( pCtx->m_hFile, pvDst, cub, &cubFileRead, nullptr );
		cubRead = cubFileRead;
	}
	return static_cast<u32>( cubRead );
}

} // namespace vac::workers::image_scan
