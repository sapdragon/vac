// @binary: a8848995
#include "internal/types.hpp"
#include "bootstrap/bootstrap.hpp"
#include "core/vac_util.hpp"
#include "crt/intrinsics.hpp"
#include "file/file.hpp"
#include "util/encoding.hpp"
#include "util/hashing.hpp"

namespace vac::workers::process_file_identity
{

namespace
{

constexpr u32 k_cubDirectoryBuffer = 0x40000;

// @orig: 53 55 8B E9 56 57 8B 7D
EEntryFlags ClassifyEntry( const FILE_ID_BOTH_DIR_INFO &entry, u32 unNowHigh ) noexcept
{
	const u32 unAttributes = entry.FileAttributes;
	EEntryFlags eFlags = ( unAttributes & FILE_ATTRIBUTE_DIRECTORY ) ? EEntryFlags::Directory : EEntryFlags::None;
	if ( unAttributes & FILE_ATTRIBUTE_READONLY )
		eFlags |= EEntryFlags::ReadOnly;
	if ( unAttributes & FILE_ATTRIBUTE_HIDDEN )
		eFlags |= EEntryFlags::Hidden;
	if ( unAttributes & FILE_ATTRIBUTE_SYSTEM )
		eFlags |= EEntryFlags::System;
	if ( unAttributes & ~static_cast<u32>( FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM |
	                                       FILE_ATTRIBUTE_DIRECTORY ) )
		eFlags |= EEntryFlags::OtherAttributes;

	if ( entry.AllocationSize.HighPart > 0 || entry.AllocationSize.LowPart > 0x1000000 )
		eFlags |= EEntryFlags::Large;
	else if ( !entry.AllocationSize.LowPart )
		eFlags |= EEntryFlags::Empty;
	else if ( entry.AllocationSize.LowPart < 0x1000 )
		eFlags |= EEntryFlags::Small;

	if ( entry.LastWriteTime.QuadPart == entry.CreationTime.QuadPart )
		eFlags |= EEntryFlags::NeverWritten;

	const u32 unCreationHigh = static_cast<u32>( entry.CreationTime.HighPart );
	if ( unCreationHigh <= unNowHigh )
	{
		const u32 unAge = unNowHigh - unCreationHigh;
		if ( unAge < 0x10 )
			eFlags |= EEntryFlags::AgeTier0;
		if ( unAge < 0x191 )
			eFlags |= EEntryFlags::AgeTier1;
		if ( unAge < 0xAFD )
			eFlags |= EEntryFlags::AgeTier2;
		if ( unAge < 0x2F17 )
			eFlags |= EEntryFlags::AgeTier3;
	}
	return eFlags;
}

} // namespace

// @orig: 81 EC ? ? ? ? 83 4C 24
u16 EnumerateDirectory( DirectoryReport_t &report, u32 unIncludeMask, u32 unExcludeMask, const wchar_t *pwszPath,
                        u32 unVolume, FileId_t fileId, u8 iParent ) noexcept
{
	if ( !g_pImports->GetFileInformationByHandleEx )
		return static_cast<u16>( EScanStatus::BootstrapFailed );

	FILETIME now;
	g_pImports->GetSystemTimeAsFileTime( &now );

	HANDLE hDirectory = INVALID_HANDLE_VALUE;
	if ( unVolume && ( fileId.m_unLow || fileId.m_unHigh ) )
	{
		u32 unLastError = 0;
		const u64 ulFileId = ( static_cast<u64>( fileId.m_unHigh ) << 32 ) | fileId.m_unLow;
		static_cast<void>(
		    file::OpenByVolumeAndId( g_pImports, unVolume, ulFileId, FILE_GENERIC_READ, &hDirectory, &unLastError ) );
	}
	else
	{
		if ( !pwszPath || !*pwszPath )
			return static_cast<u16>( EScanStatus::OpenFailed );

		// @note / sapdragon: the template handle really is INVALID_HANDLE_VALUE in the original
		hDirectory =
		    g_pImports->CreateFileW( pwszPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		                             nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, INVALID_HANDLE_VALUE );
	}
	if ( hDirectory == INVALID_HANDLE_VALUE )
		return static_cast<u16>( EScanStatus::OpenFailed );

	// @note / sapdragon: leaves the directory open on failure. same as the original
	auto *pubBuffer = static_cast<u8 *>( util::HeapAlloc( k_cubDirectoryBuffer ) );
	if ( !pubBuffer )
		return static_cast<u16>( EScanStatus::OutOfMemory );

	wchar_t wszName[1024];
	char szName[1024];
	BY_HANDLE_FILE_INFORMATION info;

	for ( ;; )
	{
		if ( !g_pImports->GetFileInformationByHandle( hDirectory, &info ) )
		{
			report.m_unInfoError = g_pImports->GetLastError();
			break;
		}

		if ( !report.m_unVolume )
		{
			report.m_unVolume = info.dwVolumeSerialNumber;
			report.m_RootId.m_unLow = info.nFileIndexLow;
			report.m_RootId.m_unHigh = info.nFileIndexHigh;
		}
		if ( report.m_unVolume != info.dwVolumeSerialNumber )
		{
			report.m_unMismatchedVolume = info.dwVolumeSerialNumber;
			break;
		}

		memset( pubBuffer, 0, k_cubDirectoryBuffer );
		const BOOL bQueried = g_pImports->GetFileInformationByHandleEx( hDirectory, FileIdBothDirectoryInfo, pubBuffer,
		                                                                k_cubDirectoryBuffer );
		if ( bQueried )
		{
			const u8 *pubEntry = pubBuffer;
			for ( ;; )
			{
				const auto &entry = *reinterpret_cast<const FILE_ID_BOTH_DIR_INFO *>( pubEntry );
				const u32 ibNext = entry.NextEntryOffset;
				const bool bDirectory = ( entry.FileAttributes & FILE_ATTRIBUTE_DIRECTORY ) != 0;

				memset( wszName, 0, sizeof( wszName ) );
				const u32 cubNameCopied = entry.FileNameLength < sizeof( wszName ) - sizeof( wchar_t )
				                              ? entry.FileNameLength
				                              : sizeof( wszName ) - sizeof( wchar_t );
				memcpy( wszName, entry.FileName, cubNameCopied );
				util::encoding::WideToUtf8Bounded( g_pImports, wszName, szName, sizeof( szName ) );

				// @note / sapdragon: an approximation of seconds since 1970. the signed shift matters for older files, keep it
				const u64 ulSinceEpoch = static_cast<u64>( entry.CreationTime.QuadPart ) + 0xFE624E212AC18000;
				const i32 nHigh = static_cast<i32>( ulSinceEpoch >> 32 );
				const u32 unCreationTime = 429 * static_cast<u32>( nHigh ) +
				                           static_cast<u32>( ulSinceEpoch ) / 10000000 + static_cast<u32>( nHigh >> 1 );

				const EEntryFlags eFlags = ClassifyEntry( entry, now.dwHighDateTime );
				const u32 cubName = entry.FileNameLength;
				EEntryFlags eTestedFlags = eFlags;

				bool bSkip = false;
				if ( unIncludeMask )
				{
					if ( !HasFlag( eFlags, static_cast<EEntryFlags>( unIncludeMask ) ) )
						bSkip = true;
					else if ( HasFlag( static_cast<EEntryFlags>( unIncludeMask ), EEntryFlags::Directory ) )
						eTestedFlags = eFlags & static_cast<EEntryFlags>( ~static_cast<u16>( EEntryFlags::Empty ) );
				}

				if ( !bSkip )
				{
					if ( unExcludeMask && HasFlag( eTestedFlags, static_cast<EEntryFlags>( unExcludeMask ) ) )
						bSkip = true;
					else if ( bDirectory && ( ( cubName == 2 && wszName[0] == L'.' ) ||
					                          ( cubName == 4 && wszName[0] == L'.' && wszName[1] == L'.' ) ) )
						bSkip = true;
				}

				if ( bSkip )
				{
					++report.m_cSkipped;
				}
				else
				{
					DirectoryRecord_t &record = report.m_rgRecords[report.m_cRecords];
					record.m_FileId.m_unLow = static_cast<u32>( entry.FileId.LowPart );
					record.m_FileId.m_unHigh = static_cast<u32>( entry.FileId.HighPart );
					record.m_unNameHash =
					    util::hashing::PathHashBytes( reinterpret_cast<const u8 *>( szName ), cubNameCopied / 2 );
					record.m_eFlags = eFlags;
					record.m_iParent = iParent;
					record.m_unCreationTime = unCreationTime;
					if ( bDirectory )
					{
						++report.m_cDirectories;
						record.m_iDirectory = static_cast<u8>( report.m_cDirectories );
					}
					else
					{
						record.m_iDirectory = 0;
					}

					if ( ++report.m_cRecords >= ARRAYSIZE( report.m_rgRecords ) )
						break;
				}

				pubEntry += ibNext;
				if ( !ibNext )
					break;
			}
		}

		if ( report.m_cRecords >= ARRAYSIZE( report.m_rgRecords ) || !bQueried )
			break;
	}

	util::HeapFree( pubBuffer );
	g_pImports->CloseHandle( hDirectory );
	return 0;
}

// @orig: 51 53 55 56 8B F1 33 DB
void ExpandDirectories( DirectoryReport_t &report, u32 unIncludeMask, u32 unExcludeMask ) noexcept
{
	if ( report.m_cRecords >= ARRAYSIZE( report.m_rgRecords ) )
		return;

	for ( u32 iRecord = 0; iRecord < report.m_cRecords; ++iRecord )
	{
		const DirectoryRecord_t &record = report.m_rgRecords[iRecord];
		if ( HasFlag( record.m_eFlags, EEntryFlags::Directory ) )
		{
			++report.m_cExpanded;
			report.m_iExpanded = static_cast<u16>( iRecord );

			const u16 unStatus = EnumerateDirectory( report, unIncludeMask, unExcludeMask, nullptr, report.m_unVolume,
			                                         record.m_FileId, record.m_iDirectory );
			report.m_unExpandStatus = unStatus;
			if ( unStatus )
			{
				report.m_unOpenError = g_pImports->GetLastError();
				return;
			}
		}

		if ( report.m_cRecords >= ARRAYSIZE( report.m_rgRecords ) )
			return;
	}
}

} // namespace vac::workers::process_file_identity
