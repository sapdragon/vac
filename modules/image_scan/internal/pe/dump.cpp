// @binary: 33211402
#include "../scanner.hpp"
#include "crt/intrinsics.hpp"
#include "util/strings.hpp"

namespace vac::workers::image_scan
{

namespace
{

void StoreHashResult( u32 *pcubField, const HybridHash_t &hash ) noexcept
{
	*pcubField ^= ( hash.m_cubTotal ^ *pcubField ) & k_unByteCountMask;
}

} // namespace

// @orig: 81 EC ? ? ? ? 53 55 56 57 8B F9
void DumpModuleInfo( ScannerContext_t *pCtx, ModuleReport_t *pModule ) noexcept
{
	pModule->m_cSections = static_cast<u8>( pCtx->m_FileHeader.NumberOfSections );
	pModule->m_unTimeDateStamp = pCtx->m_FileHeader.TimeDateStamp;
	if ( pCtx->m_bPe64 )
	{
		pModule->m_unEntryPoint = pCtx->m_OptionalHeader64.AddressOfEntryPoint;
		pModule->m_unCheckSum = pCtx->m_OptionalHeader64.CheckSum;
	}
	else
	{
		pModule->m_unEntryPoint = pCtx->m_OptionalHeader32.AddressOfEntryPoint;
		pModule->m_unCheckSum = pCtx->m_OptionalHeader32.CheckSum;
	}

	HybridHash_t hash;
	hash.m_eMode = EHashMode::Md5;
	ResetHybridHash( &hash );

	if ( !pCtx->m_bPe64 )
	{
		pCtx->m_bLoadedImagePass = 1;
		if ( HashAllSections( pCtx, &hash ) )
		{
			StoreHashResult( &pModule->m_cubLoadedImage, hash );
			memcpy( pModule->m_rgubLoadedImageMd5, hash.m_rgubDigest, sizeof( hash.m_rgubDigest ) );
		}
		else
		{
			pModule->m_cubLoadedImage |= k_unFailedFlag;
		}
		pCtx->m_bLoadedImagePass = 0;
		ResetHybridHash( &hash );
	}

	if ( HashAllSections( pCtx, &hash ) )
	{
		StoreHashResult( &pModule->m_cubImageHash, hash );
		memcpy( pModule->m_rgubImageMd5, hash.m_rgubDigest, sizeof( hash.m_rgubDigest ) );
	}
	else
	{
		pModule->m_cubImageHash |= k_unFailedFlag;
	}
	ResetHybridHash( &hash );

	u32 cReported = ARRAYSIZE( pModule->m_rgSections );
	if ( pCtx->m_FileHeader.NumberOfSections <= ARRAYSIZE( pModule->m_rgSections ) )
		cReported = pCtx->m_FileHeader.NumberOfSections;

	for ( u32 iSection = 0; iSection < cReported; ++iSection )
	{
		const IMAGE_SECTION_HEADER *pSection = &pCtx->m_pSections[iSection];
		ResetHybridHash( &hash );
		if ( iSection < pCtx->m_FileHeader.NumberOfSections && HashSectionWithFixups( pCtx, pSection, &hash ) )
		{
			if ( HasFlag( hash.m_eMode, EHashMode::Md5 ) )
				hash.m_Md5.Final( hash.m_rgubDigest );
			StoreHashResult( &pModule->m_rgcubSections[iSection], hash );
			memcpy( pModule->m_rgubSectionMd5[iSection], hash.m_rgubDigest, sizeof( hash.m_rgubDigest ) );
		}
		else
		{
			pModule->m_rgcubSections[iSection] |= k_unFailedFlag;
		}

		SectionRecord_t &record = pModule->m_rgSections[iSection];
		memcpy( record.m_rgchName, pSection->Name, sizeof( record.m_rgchName ) );
		record.m_unCharacteristics = pSection->Characteristics;
		record.m_cubRaw = pSection->SizeOfRawData;
		record.m_unReserved = 0;
		record.m_unVirtualAddress = pSection->VirtualAddress;
	}

	u32 cubIcon = 0;
	if ( HashBestIconResource( pCtx, pModule->m_rgubIconMd5, &cubIcon ) )
		pModule->m_cubIcon ^= ( cubIcon ^ pModule->m_cubIcon ) & k_unByteCountMask;
	else
		pModule->m_cubIcon |= k_unFailedFlag;

	pModule->m_cReportedHashes = static_cast<u8>( cReported + 4 );

	if ( ExtractPdbInfo( pCtx ) == EScanStatus::Ok )
		util::CopyA( pModule->m_szPdbPath, pCtx->m_szPdbPath, sizeof( pModule->m_szPdbPath ) );

	ResetHybridHash( &hash );
}

// @orig: 55 8B EC 51 53
void DumpPeHeaders( ScannerContext_t *pCtx, PeHeadersReport_t *pPeHeaders ) noexcept
{
	memset( pPeHeaders, 0, sizeof( *pPeHeaders ) );
	memcpy( &pPeHeaders->m_FileHeader, &pCtx->m_RawFileHeader, sizeof( pPeHeaders->m_FileHeader ) );
	memcpy( pPeHeaders->m_rgubOptionalHeader,
	        pCtx->m_bPe64 ? static_cast<const void *>( &pCtx->m_OptionalHeader64 ) : &pCtx->m_OptionalHeader32,
	        sizeof( pPeHeaders->m_rgubOptionalHeader ) );
	memcpy( pPeHeaders->m_rgubDosStub, pCtx->m_rgubDosStub, sizeof( pPeHeaders->m_rgubDosStub ) );

	// @note / sapdragon: the overlay can open with a WIN_CERTIFICATE. a sane one means an embedded signature, so the
	// catalog lookup is skipped
	bool bLookUpCatalog = true;
	const IMAGE_SECTION_HEADER *pExtra = FindExtraSection( pCtx );
	if ( pExtra &&
	     ReaderSeek( pCtx, pCtx->m_hFile != INVALID_HANDLE_VALUE ? pExtra->PointerToRawData : pExtra->VirtualAddress,
	                 false ) )
	{
		const u8 *pubWindow = ReaderWindow( pCtx, sizeof( pPeHeaders->m_rgubOverlayHead ) );
		if ( pubWindow )
		{
			memcpy( pPeHeaders->m_rgubOverlayHead, pubWindow, sizeof( pPeHeaders->m_rgubOverlayHead ) );

			const auto *pCertificate = reinterpret_cast<const WIN_CERTIFICATE *>( pPeHeaders->m_rgubOverlayHead );
			if ( pCertificate->dwLength >= offsetof( WIN_CERTIFICATE, bCertificate ) &&
			     ( pCertificate->wRevision == WIN_CERT_REVISION_1_0 ||
			       pCertificate->wRevision == WIN_CERT_REVISION_2_0 ) )
			{
				if ( pCertificate->wCertificateType )
					bLookUpCatalog = pCertificate->wCertificateType > WIN_CERT_TYPE_TS_STACK_SIGNED;
			}
		}
	}

	pPeHeaders->m_bVerified = VerifySignatureAndCatalog( pCtx, bLookUpCatalog );
	pPeHeaders->m_bCatalogValid = pCtx->m_bCatalogValid;
	pPeHeaders->m_unWinTrustStatus = pCtx->m_unWinTrustStatus;
	pPeHeaders->m_unWinTrustLastError = pCtx->m_unWinTrustLastError;

	if ( pCtx->m_bCatalogValid )
	{
		u32 cubPath = util::StrLenA( pCtx->m_szCatalogPath ) + 1;
		if ( cubPath > sizeof( pPeHeaders->m_szCatalogPath ) )
			cubPath = sizeof( pPeHeaders->m_szCatalogPath );
		memcpy( pPeHeaders->m_szCatalogPath, pCtx->m_szCatalogPath, cubPath );
		pPeHeaders->m_szCatalogPath[sizeof( pPeHeaders->m_szCatalogPath ) - 1] = 0;
	}
	else
	{
		memcpy( &pPeHeaders->m_Issuer, &pCtx->m_Issuer, sizeof( pPeHeaders->m_Issuer ) );
		memcpy( &pPeHeaders->m_Signer, &pCtx->m_Signer, sizeof( pPeHeaders->m_Signer ) );
	}
}

} // namespace vac::workers::image_scan
