// @binary: 33211402
#include "verify/cert_chain.hpp"
#include "crt/intrinsics.hpp"
#include "util/encoding.hpp"

namespace vac::verify
{

namespace
{

// @orig: 55 8B EC 83 EC ? 53 56 8B F1
void LoadSignerCertificate( const SystemImports_t *pImports, CertContextSet_t *pSet ) noexcept
{
	if ( !pSet->m_hMsg || !pImports->CryptMsgGetParam || !pImports->CertFindCertificateInStore || !pSet->m_hStore )
		return;

	DWORD cubSignerInfo = 0;
	pImports->CryptMsgGetParam( pSet->m_hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &cubSignerInfo );
	if ( !cubSignerInfo )
		return;

	auto *pSignerInfo = static_cast<CMSG_SIGNER_INFO *>( pImports->LocalAlloc( LPTR, cubSignerInfo ) );
	if ( !pSignerInfo )
		return;

	PCCERT_CONTEXT pSigner = nullptr;
	if ( pImports->CryptMsgGetParam( pSet->m_hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &cubSignerInfo ) )
	{
		CERT_INFO criteria{};
		criteria.Issuer = pSignerInfo->Issuer;
		criteria.SerialNumber = pSignerInfo->SerialNumber;
		pSigner = pImports->CertFindCertificateInStore( pSet->m_hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
		                                                CERT_FIND_SUBJECT_CERT, &criteria, nullptr );
	}
	pImports->LocalFree( pSignerInfo );

	pSet->m_pSigner = pSigner;
	pSet->m_bSignerBorrowed = false;
}

// @orig: inlined
bool LoadSignerAndIssuer( const SystemImports_t *pImports, CertContextSet_t *pSet ) noexcept
{
	LoadSignerCertificate( pImports, pSet );

	// @note / sapdragon: CERT_FIND_SUBJECT_CERT would just find the signer again for appx signed binaries
	if ( pSet->m_pSigner && pImports->CertFindCertificateInStore )
	{
		pSet->m_pIssuer = pImports->CertFindCertificateInStore( pSet->m_hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		                                                        0, CERT_FIND_ISSUER_OF, pSet->m_pSigner, nullptr );

		// @note / sapdragon: marked borrowed, so the issuer context is never freed. a leak in the original, keep it
		pSet->m_bIssuerBorrowed = true;
	}
	return pSet->m_pSigner != nullptr;
}

// @orig: 83 39 ? 74 ? 80 79
void FreeCertificate( const SystemImports_t *pImports, PCCERT_CONTEXT pCert, bool bBorrowed ) noexcept
{
	if ( pCert && !bBorrowed && pImports->CertFreeCertificateContext )
		pImports->CertFreeCertificateContext( pCert );
}

// @orig: A1 ? ? ? ? 53 55
void GetSubjectName( const SystemImports_t *pImports, PCCERT_CONTEXT pCert, char *pszSubject ) noexcept
{
	if ( !pImports->CertGetNameStringW || !pImports->LocalAlloc || !pImports->LocalFree )
		return;

	const DWORD cChars = pImports->CertGetNameStringW( pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0 );
	if ( cChars <= 1 )
		return;

	auto *pwszName = static_cast<wchar_t *>( pImports->LocalAlloc( LPTR, cChars * sizeof( wchar_t ) ) );
	if ( !pwszName )
		return;

	if ( pImports->CertGetNameStringW( pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, pwszName, cChars ) )
		util::encoding::WideToUtf8Bounded( pImports, pwszName, pszSubject, sizeof( CertIdentity_t::m_szSubject ) );
	pImports->LocalFree( pwszName );
}

// @orig: 55 8B EC 51 8B 01
void HashCertificateSha1( const SystemImports_t *pImports, PCCERT_CONTEXT pCert, u8 *pubSha1 ) noexcept
{
	if ( !pImports->CryptHashCertificate )
		return;
	DWORD cubHash = sizeof( CertIdentity_t::m_rgubSha1 );
	pImports->CryptHashCertificate( 0, CALG_SHA1, 0, pCert->pbCertEncoded, pCert->cbCertEncoded, pubSha1, &cubHash );
}

} // namespace

// @note / sapdragon: only image_scan's rebuild opens by path, the original always goes through a mapped blob
bool OpenCertificateContext( const SystemImports_t *pImports, CertContextSet_t *pSet, const wchar_t *pwszPath ) noexcept
{
	memset( pSet, 0, sizeof( *pSet ) );
	if ( !pImports->CryptQueryObject )
		return false;

	DWORD unEncoding = 0;
	DWORD unContentType = 0;
	DWORD unFormatType = 0;
	if ( !pImports->CryptQueryObject( CERT_QUERY_OBJECT_FILE, pwszPath, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
	                                  CERT_QUERY_FORMAT_FLAG_BINARY, 0, &unEncoding, &unContentType, &unFormatType,
	                                  &pSet->m_hStore, &pSet->m_hMsg, nullptr ) )
	{
		pSet->m_unLastError = pImports->GetLastError();
		return false;
	}
	return LoadSignerAndIssuer( pImports, pSet );
}

// @orig: 55 8B EC 83 EC ? 53 56 8B 45
bool OpenCertificateContextFromBlob( const SystemImports_t *pImports, CertContextSet_t *pSet, const void *pData,
                                     u32 cubData, DWORD unContentFlags ) noexcept
{
	memset( pSet, 0, sizeof( *pSet ) );
	if ( !pImports->CryptQueryObject || !pData || !cubData )
		return false;

	CRYPT_DATA_BLOB blob{};
	blob.cbData = cubData;
	blob.pbData = static_cast<BYTE *>( const_cast<void *>( pData ) );

	DWORD unEncoding = 0;
	DWORD unContentType = 0;
	DWORD unFormatType = 0;
	if ( !pImports->CryptQueryObject( CERT_QUERY_OBJECT_BLOB, &blob, unContentFlags, CERT_QUERY_FORMAT_FLAG_BINARY, 0,
	                                  &unEncoding, &unContentType, &unFormatType, &pSet->m_hStore, &pSet->m_hMsg,
	                                  nullptr ) )
	{
		pSet->m_unLastError = pImports->GetLastError();
		return false;
	}
	return LoadSignerAndIssuer( pImports, pSet );
}

// @orig: inlined
void ExtractCertChain( const SystemImports_t *pImports, const CertContextSet_t *pSet, CertIdentity_t *pSigner,
                       CertIdentity_t *pIssuer ) noexcept
{
	if ( pSet->m_pSigner )
	{
		GetSubjectName( pImports, pSet->m_pSigner, pSigner->m_szSubject );
		HashCertificateSha1( pImports, pSet->m_pSigner, pSigner->m_rgubSha1 );
	}
	if ( pSet->m_pIssuer )
	{
		GetSubjectName( pImports, pSet->m_pIssuer, pIssuer->m_szSubject );
		HashCertificateSha1( pImports, pSet->m_pIssuer, pIssuer->m_rgubSha1 );
	}
}

// @orig: 56 8B F1 83 7E ? ? 74 ? FF 76
void ReleaseCertContext( const SystemImports_t *pImports, CertContextSet_t *pSet ) noexcept
{
	if ( pSet->m_hMsg && pImports->CryptMsgClose )
		pImports->CryptMsgClose( pSet->m_hMsg );
	if ( pSet->m_hStore && pImports->CertCloseStore )
		pImports->CertCloseStore( pSet->m_hStore, 0 );
	FreeCertificate( pImports, pSet->m_pIssuer, pSet->m_bIssuerBorrowed );
	FreeCertificate( pImports, pSet->m_pSigner, pSet->m_bSignerBorrowed );
	memset( pSet, 0, sizeof( *pSet ) );
}

} // namespace vac::verify
