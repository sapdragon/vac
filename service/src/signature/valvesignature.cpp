// @binary: 7ebac2a4
#include "signature/valvesignature.hpp"

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <bcrypt.h>
#include <ntstatus.h>
#include <wincrypt.h>

#include <cstring>
#include <string_view>
#include <vector>

#pragma comment( lib, "bcrypt.lib" )
#pragma comment( lib, "crypt32.lib" )

namespace
{

// @note / sapdragon: the signature block sits in the dos stub, right after the dos header
struct ValveSignatureHeader_t
{
	uint32_t m_unMagic;
	uint32_t m_unVersion;
	uint32_t m_cubSigned;
	uint32_t m_unReserved;
	uint8_t m_rgubSignature[128];
};
static_assert( sizeof( ValveSignatureHeader_t ) == 0x90 );

constexpr uint32_t k_unValveMagic = 0x564C56;
constexpr uint32_t k_ibSignatureHeader = sizeof( IMAGE_DOS_HEADER );

// @note / sapdragon: the first slot is an empty string in the binary, so one real key
const char k_szCodeSignatureKey[] =
    "30819D300D06092A864886F70D010101050003818B0030818702818100B1260881BDFE84463D88C6AB8DB914A2E59389"
    "3C10508B8A5ABDF692E9A5419A3EDBAE86A052849983B75E3B425C18178B260003D857DF0B6505C6CF9C84F5859FCE3B"
    "63F1FB2D4818501F6C5FA4AD1430EEB081A74ABD74CD1F4AA1FCCA3B88DD0548AED34443CEB52444EAE9099AA4FE66B2"
    "E6224D02381C248025C7044079020111";

std::vector<uint8_t> DecodeHex( std::string_view svHex )
{
	std::vector<uint8_t> rgubOut;
	if ( svHex.size() % 2 )
		return {};

	const auto NibbleValue = []( char ch ) -> int
	{
		if ( ch >= '0' && ch <= '9' )
			return ch - '0';
		if ( ch >= 'A' && ch <= 'F' )
			return ch - 'A' + 10;
		if ( ch >= 'a' && ch <= 'f' )
			return ch - 'a' + 10;
		return -1;
	};
	for ( size_t ich = 0; ich < svHex.size(); ich += 2 )
	{
		const int nHigh = NibbleValue( svHex[ich] );
		const int nLow = NibbleValue( svHex[ich + 1] );
		if ( nHigh < 0 || nLow < 0 )
			return {};
		rgubOut.push_back( static_cast<uint8_t>( ( nHigh << 4 ) | nLow ) );
	}
	return rgubOut;
}

BCRYPT_KEY_HANDLE ImportPublicKey( const char *pszHexKey )
{
	const std::vector<uint8_t> rgubDer = DecodeHex( pszHexKey );
	if ( rgubDer.empty() )
		return nullptr;

	CERT_PUBLIC_KEY_INFO *pKeyInfo = nullptr;
	DWORD cubKeyInfo = 0;
	if ( !CryptDecodeObjectEx( X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, rgubDer.data(),
	                           static_cast<DWORD>( rgubDer.size() ), CRYPT_DECODE_ALLOC_FLAG, nullptr, &pKeyInfo,
	                           &cubKeyInfo ) )
		return nullptr;

	BCRYPT_KEY_HANDLE hKey = nullptr;
	if ( !CryptImportPublicKeyInfoEx2( X509_ASN_ENCODING, pKeyInfo, 0, nullptr, &hKey ) )
		hKey = nullptr;
	LocalFree( pKeyInfo );
	return hKey;
}

bool HashSha1( const void *pvData, uint32_t cubData, uint8_t ( &rgubDigest )[20] )
{
	return BCRYPT_SUCCESS( BCryptHash( BCRYPT_SHA1_ALG_HANDLE, nullptr, 0,
	                                   static_cast<PUCHAR>( const_cast<void *>( pvData ) ), cubData, rgubDigest,
	                                   sizeof( rgubDigest ) ) );
}

// @orig: 55 8B EC 83 EC ? 83 3D ? ? ? ? ? 75 ? 33 C0 EB ? 8D 45 ? 50 6A ? 68 ? ? ? ? E8 ? ? ? ? 83 C4 ? 83 7D ? ? 89 45 ? 75 ? 68 ? ? ? ? 68 ? ? ? ? 68 ? ? ? ? E8 ? ? ? ? 83 C4 ? 84 C0 75 ? CC 83 7D
bool VerifyRSASignature( const void *pvData, uint32_t cubData, const uint8_t *pubSignature, uint32_t cubSignature,
                         const char *pszHexKey )
{
	const BCRYPT_KEY_HANDLE hKey = ImportPublicKey( pszHexKey );
	if ( !hKey )
		return false;

	uint8_t rgubDigest[20];
	bool bValid = false;
	if ( HashSha1( pvData, cubData, rgubDigest ) )
	{
		BCRYPT_PKCS1_PADDING_INFO padding{ BCRYPT_SHA1_ALGORITHM };
		bValid = BCRYPT_SUCCESS( BCryptVerifySignature( hKey, &padding, rgubDigest, sizeof( rgubDigest ),
		                                                const_cast<PUCHAR>( pubSignature ), cubSignature,
		                                                BCRYPT_PAD_PKCS1 ) );
	}
	BCryptDestroyKey( hKey );
	return bValid;
}

} // namespace

// @orig: 55 8B EC 8B 55 ? 81 EC ? ? ? ? 56 81 FA
ESignatureResult VerifyValveWin32Signature( void *pvImage, uint32_t cubImage, const char *const *ppszPublicKeys,
                                            uint32_t cPublicKeys )
{
	auto *pubImage = static_cast<uint8_t *>( pvImage );
	if ( cubImage < 0x200 )
		return ESignatureResult::NotPeImage;
	const auto *pDosHeader = static_cast<const IMAGE_DOS_HEADER *>( pvImage );
	if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
		return ESignatureResult::NotPeImage;

	const uint32_t ibNtHeaders = pDosHeader->e_lfanew;
	if ( ibNtHeaders < sizeof( IMAGE_DOS_HEADER ) || ibNtHeaders >= cubImage - sizeof( IMAGE_NT_HEADERS32 ) ||
	     *reinterpret_cast<const DWORD *>( pubImage + ibNtHeaders ) != IMAGE_NT_SIGNATURE )
		return ESignatureResult::NotPeImage;

	auto *pHeader = reinterpret_cast<ValveSignatureHeader_t *>( pubImage + k_ibSignatureHeader );
	if ( pHeader->m_unMagic != k_unValveMagic )
		return ESignatureResult::NoValveHeader;
	if ( pHeader->m_unVersion != 1 )
		return ESignatureResult::BadVersion;
	if ( cubImage < pHeader->m_cubSigned )
		return ESignatureResult::BadLength;

	auto *pHeaders32 = reinterpret_cast<IMAGE_NT_HEADERS32 *>( pubImage + ibNtHeaders );
	auto *pHeaders64 = reinterpret_cast<IMAGE_NT_HEADERS64 *>( pubImage + ibNtHeaders );
	const bool b32Bit = pHeaders32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
	if ( !b32Bit && pHeaders32->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC )
		return ESignatureResult::BadLength;

	DWORD &unCheckSum = b32Bit ? pHeaders32->OptionalHeader.CheckSum : pHeaders64->OptionalHeader.CheckSum;
	IMAGE_DATA_DIRECTORY &security = b32Bit ? pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]
	                                        : pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];

	uint8_t rgubSignature[sizeof( pHeader->m_rgubSignature )];
	memcpy( rgubSignature, pHeader->m_rgubSignature, sizeof( rgubSignature ) );
	memset( pHeader->m_rgubSignature, 0, sizeof( pHeader->m_rgubSignature ) );
	const DWORD unSavedCheckSum = unCheckSum;
	unCheckSum = 0;
	const IMAGE_DATA_DIRECTORY savedSecurity = security;
	security = {};

	bool bValid = false;
	for ( uint32_t iKey = 0; iKey < cPublicKeys && !bValid; ++iKey )
		bValid = VerifyRSASignature( pubImage, pHeader->m_cubSigned, rgubSignature, sizeof( rgubSignature ),
		                             ppszPublicKeys[iKey] );

	memcpy( pHeader->m_rgubSignature, rgubSignature, sizeof( rgubSignature ) );
	unCheckSum = unSavedCheckSum;
	security = savedSecurity;
	return bValid ? ESignatureResult::Valid : ESignatureResult::Invalid;
}

// @orig: 55 8B EC FF 35 ? ? ? ? 68
ESignatureResult VerifyValveSignature( void *pvImage, uint32_t cubImage )
{
	const char *const rgpszKeys[] = { "", k_szCodeSignatureKey };
	return VerifyValveWin32Signature( pvImage, cubImage, rgpszKeys, 2 );
}
