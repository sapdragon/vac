// @binary: 42878040
#include "file/file.hpp"
#include "crt/intrinsics.hpp"
#include "util/wstr.hpp"

namespace vac::file
{

// @orig: 8B 81 ? ? ? ? 83 F8
u32 GetFileSizeOrZero( const SystemImports_t *pImports, HANDLE hFile ) noexcept
{
	if ( hFile == INVALID_HANDLE_VALUE )
		return 0;
	const DWORD cubSize = pImports->GetFileSize( hFile, nullptr );
	return cubSize == INVALID_FILE_SIZE ? 0 : cubSize;
}

bool GetFileSize32( const SystemImports_t *pImports, HANDLE hFile, u32 *pcubSize ) noexcept
{
	*pcubSize = 0;
	if ( !pImports )
		return false;

	if ( pImports->GetFileSizeEx )
	{
		LARGE_INTEGER liSize;
		liSize.QuadPart = 0;
		if ( !pImports->GetFileSizeEx( hFile, &liSize ) || liSize.QuadPart < 0 || liSize.HighPart != 0 )
			return false;
		*pcubSize = liSize.LowPart;
		return true;
	}

	if ( pImports->GetFileSize )
	{
		DWORD unHigh = 0;
		const DWORD unLow = pImports->GetFileSize( hFile, &unHigh );
		if ( unLow == INVALID_FILE_SIZE && pImports->GetLastError && pImports->GetLastError() != NO_ERROR )
			return false;
		if ( unHigh )
			return false;
		*pcubSize = unLow;
		return true;
	}
	return false;
}

bool ReadWholeFile( const SystemImports_t *pImports, HANDLE hFile, u8 **ppubData, u32 *pcubData,
                    bool bAllowLinkedHeap ) noexcept
{
	*ppubData = nullptr;
	*pcubData = 0;
	if ( !pImports || !pImports->ReadFile )
		return false;
	if ( !bAllowLinkedHeap && ( !pImports->HeapAlloc || !pImports->HeapFree || !pImports->GetProcessHeap ) )
		return false;

	u32 cubFile = 0;
	if ( !GetFileSize32( pImports, hFile, &cubFile ) || !cubFile )
		return false;

	HANDLE hHeap = pImports->GetProcessHeap ? pImports->GetProcessHeap() : GetProcessHeap();
	auto *pubBuffer = static_cast<u8 *>( pImports->HeapAlloc ? pImports->HeapAlloc( hHeap, 0, cubFile )
	                                                         : ::HeapAlloc( hHeap, 0, cubFile ) );
	if ( !pubBuffer )
		return false;

	u32 cubTotal = 0;
	while ( cubTotal < cubFile )
	{
		DWORD cubRead = 0;
		const u32 cubWanted = ( cubFile - cubTotal ) > 0x10000u ? 0x10000u : ( cubFile - cubTotal );
		if ( !pImports->ReadFile( hFile, pubBuffer + cubTotal, cubWanted, &cubRead, nullptr ) || !cubRead )
		{
			FreeWholeFile( pImports, pubBuffer, bAllowLinkedHeap );
			return false;
		}
		cubTotal += cubRead;
	}

	*ppubData = pubBuffer;
	*pcubData = cubFile;
	return true;
}

void FreeWholeFile( const SystemImports_t *pImports, u8 *pubData, bool bAllowLinkedHeap ) noexcept
{
	if ( !bAllowLinkedHeap )
	{
		pImports->HeapFree( pImports->GetProcessHeap(), 0, pubData );
		return;
	}

	HANDLE hHeap = pImports && pImports->GetProcessHeap ? pImports->GetProcessHeap() : GetProcessHeap();
	if ( pImports && pImports->HeapFree )
		pImports->HeapFree( hHeap, 0, pubData );
	else
		::HeapFree( hHeap, 0, pubData );
}

// @orig: 81 EC ? ? ? ? 83 3D
EOpenByIdStatus OpenByVolumeAndId( const SystemImports_t *pImports, u32 unVolumeSerial, u64 ulFileId,
                                   DWORD unDesiredAccess, HANDLE *phFile, u32 *punLastError ) noexcept
{
	*phFile = INVALID_HANDLE_VALUE;
	*punLastError = 0;

	if ( !pImports || !pImports->FindFirstVolumeW || !pImports->FindNextVolumeW || !pImports->FindVolumeClose ||
	     !pImports->GetVolumeInformationW || !pImports->CreateFileW || !pImports->CloseHandle ||
	     !pImports->OpenFileById )
		return EOpenByIdStatus::ImportsMissing;

	wchar_t wszVolume[MAX_PATH];
	memset( wszVolume, 0, sizeof( wszVolume ) );
	HANDLE hFind = pImports->FindFirstVolumeW( wszVolume, MAX_PATH );
	if ( hFind == INVALID_HANDLE_VALUE )
	{
		*punLastError = pImports->GetLastError();
		return EOpenByIdStatus::FindFirstFailed;
	}

	for ( ;; )
	{
		DWORD unSerial = 0;
		if ( pImports->GetVolumeInformationW( wszVolume, nullptr, 0, &unSerial, nullptr, nullptr, nullptr, 0 ) &&
		     unSerial == unVolumeSerial )
		{
			// @note / sapdragon: without the trailing slash the volume name opens the volume itself
			const u32 cChars = util::wstr::Length( wszVolume );
			if ( cChars > 1 )
				wszVolume[cChars - 1] = 0;

			HANDLE hRoot = pImports->CreateFileW( wszVolume, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
			                                      OPEN_EXISTING, 0, nullptr );
			if ( hRoot != INVALID_HANDLE_VALUE )
			{
				FILE_ID_DESCRIPTOR descriptor{};
				descriptor.dwSize = sizeof( descriptor );
				descriptor.Type = FileIdType;
				descriptor.FileId.QuadPart = static_cast<LONGLONG>( ulFileId );

				HANDLE hFile = pImports->OpenFileById( hRoot, &descriptor, unDesiredAccess,
				                                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
				                                       FILE_FLAG_BACKUP_SEMANTICS );
				*punLastError = pImports->GetLastError();
				pImports->CloseHandle( hRoot );
				pImports->FindVolumeClose( hFind );

				if ( hFile == INVALID_HANDLE_VALUE )
					return EOpenByIdStatus::OpenFailed;
				*phFile = hFile;
				return EOpenByIdStatus::Ok;
			}
			*punLastError = pImports->GetLastError();
		}

		if ( !pImports->FindNextVolumeW( hFind, wszVolume, MAX_PATH ) )
		{
			pImports->FindVolumeClose( hFind );
			return EOpenByIdStatus::NoVolumeMatched;
		}
	}
}

} // namespace vac::file
