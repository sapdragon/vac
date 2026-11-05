#pragma once

#include "bootstrap/imports.hpp"
#include "core/layout.hpp"
#include "core/types.hpp"

namespace vac::verify
{

struct CertIdentity_t
{
	u8 m_rgubSha1[20];
	char m_szSubject[40];
};
VAC_LAYOUT( CertIdentity_t, m_szSubject, 20 );
VAC_LAYOUT_SIZE( CertIdentity_t, 60 );

struct CertContextSet_t
{
	DWORD m_unLastError;
	HCERTSTORE m_hStore;
	HCRYPTMSG m_hMsg;
	PCCERT_CONTEXT m_pSigner;
	bool m_bSignerBorrowed;
	PCCERT_CONTEXT m_pIssuer;
	bool m_bIssuerBorrowed;
};
VAC_LAYOUT( CertContextSet_t, m_hStore, 0x04 );
VAC_LAYOUT( CertContextSet_t, m_hMsg, 0x08 );
VAC_LAYOUT( CertContextSet_t, m_pSigner, 0x0C );
VAC_LAYOUT( CertContextSet_t, m_bSignerBorrowed, 0x10 );
VAC_LAYOUT( CertContextSet_t, m_pIssuer, 0x14 );
VAC_LAYOUT( CertContextSet_t, m_bIssuerBorrowed, 0x18 );
VAC_LAYOUT_SIZE( CertContextSet_t, 0x1C );

[[nodiscard]] bool OpenCertificateContext( const SystemImports_t *pImports, CertContextSet_t *pSet,
                                           const wchar_t *pwszPath ) noexcept;
[[nodiscard]] bool OpenCertificateContextFromBlob( const SystemImports_t *pImports, CertContextSet_t *pSet,
                                                   const void *pData, u32 cubData, DWORD unContentFlags ) noexcept;

void ExtractCertChain( const SystemImports_t *pImports, const CertContextSet_t *pSet, CertIdentity_t *pSigner,
                       CertIdentity_t *pIssuer ) noexcept;

void ReleaseCertContext( const SystemImports_t *pImports, CertContextSet_t *pSet ) noexcept;

} // namespace vac::verify
