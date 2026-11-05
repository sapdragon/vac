// @binary: a07ed54b
#include "internal/types.hpp"
#include "bootstrap/bootstrap.hpp"
#include "crt/intrinsics.hpp"
#include "file/file.hpp"
#include "util/hashing.hpp"

namespace vac::workers::system_info
{

namespace
{

constexpr u32 k_cVolumeFieldChars = 50;

u32 HashWide( const wchar_t *pwszText ) noexcept
{
	// @note / sapdragon: the length is in chars but the hash walks bytes, so only half the string counts
	return util::hashing::PathHashBytes( reinterpret_cast<const u8 *>( pwszText ),
	                                     static_cast<u32>( lstrlenW( pwszText ) ) );
}

} // namespace

// @orig: 55 8D 6C 24
bool QueryFileIdentity( const wchar_t *pwszPath, u32 *punVolumeSerial, u64 *pulFileId,
                        const SystemImports_t *pImports ) noexcept
{
	if ( !pImports->GetFileInformationByHandle )
		return false;

	const HANDLE hFile = pImports->CreateFileW( pwszPath, FILE_GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
	                                            FILE_FLAG_BACKUP_SEMANTICS, nullptr );
	if ( hFile == INVALID_HANDLE_VALUE || !pImports->GetFileInformationByHandleEx )
		return false;

	u8 rgubInfo[132];
	memset( rgubInfo, 0, sizeof( rgubInfo ) );
	const BOOL bOk =
	    pImports->GetFileInformationByHandleEx( hFile, FileIdBothDirectoryInfo, rgubInfo, sizeof( rgubInfo ) );

	*punVolumeSerial = 0;
	if ( bOk && pImports->GetVolumeInformationByHandleW )
		pImports->GetVolumeInformationByHandleW( hFile, nullptr, 0, reinterpret_cast<LPDWORD>( punVolumeSerial ),
		                                         nullptr, nullptr, nullptr, 0 );

	pImports->CloseHandle( hFile );
	if ( !bOk )
	{
		pImports->GetLastError();
		return false;
	}

	memcpy( pulFileId, &rgubInfo[offsetof( FILE_ID_BOTH_DIR_INFO, FileId.LowPart )], sizeof( u32 ) );
	memcpy( reinterpret_cast<u8 *>( pulFileId ) + sizeof( u32 ),
	        &rgubInfo[offsetof( FILE_ID_BOTH_DIR_INFO, FileId.HighPart )], sizeof( u32 ) );
	return true;
}

// @orig: 81 EC ? ? ? ? 53 55 56 33 F6
u32 CollectVolumes( VolumeEntry_t *pEntries, const SystemImports_t *pImports ) noexcept
{
	if ( !pImports->FindFirstVolumeW )
		return 0;

	wchar_t wszVolume[MAX_PATH + 2];
	memset( wszVolume, 0, MAX_PATH * sizeof( wchar_t ) );
	const HANDLE hFind = pImports->FindFirstVolumeW( wszVolume, MAX_PATH );
	if ( hFind == INVALID_HANDLE_VALUE )
	{
		pImports->GetLastError();
		return 0;
	}

	if ( !pImports->GetVolumeInformationW || !pImports->GetDriveTypeW || !pImports->GetVolumePathNamesForVolumeNameW )
		return 0;

	u32 cVolumes = 0;
	do
	{
		VolumeEntry_t entry;
		memset( &entry, 0, sizeof( entry ) );
		entry.m_unNameHash = HashWide( wszVolume );

		DWORD unSerial = 0;
		DWORD unFlags = 0;
		wchar_t wszLabel[k_cVolumeFieldChars + 2];
		wchar_t wszFileSystem[k_cVolumeFieldChars + 2];
		if ( pImports->GetVolumeInformationW( wszVolume, wszLabel, k_cVolumeFieldChars, &unSerial, nullptr, &unFlags,
		                                      wszFileSystem, k_cVolumeFieldChars ) )
		{
			entry.m_unFileSystemFlags = unFlags;
			entry.m_unSerial = unSerial;
			entry.m_unLabelHash = HashWide( wszLabel );
			entry.m_unFileSystemHash = HashWide( wszFileSystem );
		}
		else
		{
			entry.m_unInfoError = pImports->GetLastError();
		}

		entry.m_unDriveType = static_cast<u16>( pImports->GetDriveTypeW( wszVolume ) );

		wchar_t wszMountPoints[k_cVolumeFieldChars + 2];
		DWORD cchMountPoints;
		if ( pImports->GetVolumePathNamesForVolumeNameW( wszVolume, wszMountPoints, k_cVolumeFieldChars,
		                                                 &cchMountPoints ) )
		{
			entry.m_cchMountPoints = static_cast<u16>( cchMountPoints );
			entry.m_unMountPointHashOrError = HashWide( wszMountPoints );
		}
		else
		{
			entry.m_cchMountPoints = 0;
			entry.m_unMountPointHashOrError = pImports->GetLastError();
		}

		if ( cVolumes < ARRAYSIZE( Report_t::m_rgVolumes ) )
			pEntries[cVolumes] = entry;
		++cVolumes;
	} while ( pImports->FindNextVolumeW( hFind, wszVolume, MAX_PATH ) );

	pImports->FindVolumeClose( hFind );
	return cVolumes;
}

} // namespace vac::workers::system_info
