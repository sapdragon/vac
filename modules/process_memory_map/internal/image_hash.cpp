// @binary: 8d88e017
#include "crt/intrinsics.hpp"
#include "crypto/hash/md5.hpp"
#include "internal/pe_reader.hpp"
#include "internal/report_builder.hpp"

namespace vac::workers::process_memory_map
{

namespace
{

// @note / sapdragon: only a read of zero bytes ends the loop, a read that keeps failing spins forever. valve's
// @orig: B8 ? ? ? ? E8 ? ? ? ? A1
u32 HashWholeFile( const wchar_t *pwszPath, u8 *pubDigest, const SystemImports_t *pImports ) noexcept
{
	const HANDLE hFile = pImports->CreateFileW( pwszPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
	                                            FILE_ATTRIBUTE_NORMAL, nullptr );
	if ( hFile == INVALID_HANDLE_VALUE )
		return 0;

	crypto::hash::Md5_t md5;
	u8 rgubChunk[4096];
	u32 cubTotal = 0;
	for ( ;; )
	{
		DWORD cubRead = 0;
		if ( pImports->ReadFile( hFile, rgubChunk, sizeof( rgubChunk ), &cubRead, nullptr ) && !cubRead )
			break;
		md5.Update( rgubChunk, cubRead );
		cubTotal += cubRead;
	}

	pImports->CloseHandle( hFile );
	md5.Final( pubDigest );
	return cubTotal;
}

// @orig: 53 55 56 8B F1 57 8B 7C 24
void AddImageHash( ReportBuilder_t &builder, u64 ulBase, EHashSource eSource,
                   const BY_HANDLE_FILE_INFORMATION &information, const u8 *pubDigest ) noexcept
{
	u8 *pubHash = builder.m_pubHashWrite;
	if ( builder.m_bWideRecords )
	{
		auto *pRecord = reinterpret_cast<ImageHashRecord64_t *>( pubHash );
		pRecord->m_unBaseAndSource = static_cast<u32>( ulBase ) | static_cast<u32>( eSource );
		pRecord->m_unBaseHigh = static_cast<u32>( ulBase >> 32 );
		pRecord->m_unVolumeSerial = information.dwVolumeSerialNumber;
		pRecord->m_unFileIndexLow = information.nFileIndexLow;
		pRecord->m_unFileIndexHigh = information.nFileIndexHigh;
		memcpy( pRecord->m_rgubDigest, pubDigest, crypto::hash::k_cubMd5Digest );
		builder.m_pubHashWrite = pubHash + sizeof( ImageHashRecord64_t );
	}
	else
	{
		auto *pRecord = reinterpret_cast<ImageHashRecord32_t *>( pubHash );
		pRecord->m_unBaseAndSource = static_cast<u32>( eSource ) | static_cast<u32>( ulBase );
		pRecord->m_unVolumeSerial = information.dwVolumeSerialNumber;
		pRecord->m_unFileIndexLow = information.nFileIndexLow;
		pRecord->m_unFileIndexHigh = information.nFileIndexHigh;
		memcpy( pRecord->m_rgubDigest, pubDigest, crypto::hash::k_cubMd5Digest );
		builder.m_pubHashWrite = pubHash + sizeof( ImageHashRecord32_t );
	}
	++builder.m_cHashes;
}

} // namespace

// @orig: B8 ? ? ? ? E8 ? ? ? ? 53 55
bool HashImageIntoTable( ReportBuilder_t &builder, const ProcessContext_t &context, const AllocationWalk_t &walk,
                         const wchar_t *pwszPath, const SystemImports_t *pImports ) noexcept
{
	CPeReader memoryReader( pImports );
	u8 rgubDigest[crypto::hash::k_cubMd5Digest];
	memset( rgubDigest, 0, sizeof( rgubDigest ) );

	BY_HANDLE_FILE_INFORMATION information;
	memset( &information, 0, sizeof( information ) );

	bool bHashed = false;
	EHashSource eSource = EHashSource::RawFile;
	if ( *pwszPath )
	{
		const HANDLE hFile = pImports->CreateFileW( pwszPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		                                            FILE_ATTRIBUTE_NORMAL, nullptr );
		if ( hFile != INVALID_HANDLE_VALUE && hFile )
		{
			if ( !pImports->GetFileInformationByHandle( hFile, &information ) )
			{
				information.dwVolumeSerialNumber = 0;
				information.nFileIndexLow = 0;
				information.nFileIndexHigh = 0;
			}

			CPeReader fileReader( pImports );
			fileReader.Release();
			if ( !fileReader.AttachFile( hFile ) || fileReader.ParseFile() != EScanStatus::Ok )
			{
				// @note / sapdragon: a failed parse already closed it, so this closes the handle twice. valve's
				pImports->CloseHandle( hFile );
			}
			else if ( fileReader.HashImage( rgubDigest ) )
			{
				bHashed = true;
				eSource = EHashSource::NormalizedFile;
			}

			if ( !bHashed && HashWholeFile( pwszPath, rgubDigest, pImports ) )
				bHashed = true;

			fileReader.Release();
			fileReader.CloseSource();
		}
	}

	if ( !bHashed && memoryReader.ParseProcessImage( walk.m_ulFirstCommitted, context.m_hProcess ) == EScanStatus::Ok &&
	     memoryReader.HashImage( rgubDigest ) )
	{
		eSource |= EHashSource::Memory;
		bHashed = true;
	}

	if ( bHashed )
		AddImageHash( builder, walk.m_First.AllocationBase, eSource, information, rgubDigest );

	memoryReader.Release();
	memoryReader.CloseSource();
	return bHashed;
}

} // namespace vac::workers::process_memory_map
