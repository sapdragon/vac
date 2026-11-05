// Known-answer tests for the SDK. Built with the normal CRT, so crt/intrinsics.cpp stays out.
// The answers come from tests/sdk/known_answers.py, which does not touch the code under test.
//
//     build/tests/sdk_tests.exe     exit code 0 when everything passes

#include "bootstrap/imports.hpp"
#include "compress/lz4.hpp"
#include "core/module.hpp"
#include "core/packets.hpp"
#include "crypto/bigint/bigint.hpp"
#include "crypto/hash/crc32.hpp"
#include "crypto/hash/hash488781ed.hpp"
#include "crypto/hash/md5.hpp"
#include "crypto/ice/ice.hpp"
#include "crypto/random/park_miller.hpp"
#include "crypto/rsa/rsa.hpp"
#include "file/file.hpp"
#include "nt/nt.hpp"
#include "pe/pe.hpp"
#include "process/process.hpp"
#include "util/asn1.hpp"
#include "util/encoding.hpp"
#include "util/hashing.hpp"
#include "util/strings.hpp"
#include "util/util.hpp"
#include "util/win32.hpp"
#include "util/wstr.hpp"
#include "util/xor_string.hpp"
#include "verify/cert_chain.hpp"

#include <intrin.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

using namespace vac;

namespace
{

struct NormalizedParams_t
{
	u32 m_unLoadedBase32;
	bool m_bAppendOverlaySection;
};

#include "known_answers.inl"

namespace reference
{
inline constexpr u32 kLz4HashLog = 13u;
inline constexpr u32 kLz4MinMatch = 4u;

namespace shim
{
inline u32 read32( const void *p ) noexcept
{
	u32 v = 0;
	std::memcpy( &v, p, sizeof( v ) );
	return v;
}
inline void write16( void *p, u16 v ) noexcept
{
	std::memcpy( p, &v, sizeof( v ) );
}
} // namespace shim

} // namespace reference
} // namespace

// The reference spells its helpers vac::util::read32 and vac::util::write16, the old SDK names.
namespace vac::util
{
using ::reference::shim::read32;
using ::reference::shim::write16;
} // namespace vac::util

namespace
{
namespace reference
{
#include "lz4_reference.inl"
} // namespace reference

int g_cChecks = 0;
int g_cFailures = 0;

void Report( bool bPassed, const char *pszExpression, int nLine )
{
	++g_cChecks;
	if ( !bPassed )
	{
		++g_cFailures;
		std::printf( "FAILED line %d: %s\n", nLine, pszExpression );
	}
}

#define CHECK( expression ) Report( static_cast<bool>( expression ), #expression, __LINE__ )

bool BytesEqual( const void *pA, const void *pB, usize cub )
{
	return std::memcmp( pA, pB, cub ) == 0;
}

std::vector<u8> BignumBytes( const crypto::bigint::Bignum_t &value )
{
	std::vector<u8> rgub;
	const u32 cub = ( value.m_cBits + 7 ) >> 3;
	const auto *pub = reinterpret_cast<const u8 *>( value.m_punData );
	for ( u32 ib = 0; ib < cub; ++ib )
		rgub.push_back( pub[cub - 1 - ib] );
	return rgub;
}

template <usize cubExpected>
bool BignumEquals( const crypto::bigint::Bignum_t &value, const u8 ( &rgubExpected )[cubExpected] )
{
	// The expected values can carry leading zeros from a fixed-width encoding.
	usize ibFirst = 0;
	while ( ibFirst < cubExpected && !rgubExpected[ibFirst] )
		++ibFirst;
	const std::vector<u8> rgub = BignumBytes( value );
	return rgub.size() == cubExpected - ibFirst && BytesEqual( rgub.data(), rgubExpected + ibFirst, rgub.size() );
}

constexpr bool IceWorksAtCompileTime()
{
	constexpr u8 rgubKey[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67 };
	constexpr u8 rgubPlain[8] = { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
	constexpr u8 rgubCipher[8] = { 0x7D, 0x6E, 0xF1, 0xEF, 0x30, 0xD4, 0x7A, 0x96 };
	const crypto::ice::IceKey_t key{ rgubKey };
	u8 rgubOut[8]{};
	u8 rgubBack[8]{};
	crypto::ice::EncryptBlock( key, rgubPlain, rgubOut );
	crypto::ice::DecryptBlock( key, rgubOut, rgubBack );
	for ( usize ib = 0; ib < 8; ++ib )
	{
		if ( rgubOut[ib] != rgubCipher[ib] || rgubBack[ib] != rgubPlain[ib] )
			return false;
	}
	return true;
}
static_assert( IceWorksAtCompileTime() );

void TestIce()
{
	using namespace crypto::ice;

	for ( unsigned iVector = 0; iVector < k_cIceVectors; ++iVector )
	{
		const u8 *pubKey = k_rgubIceVectors + iVector * 24;
		const u8 *pubPlain = pubKey + 8;
		const u8 *pubCipher = pubKey + 16;

		u8 rgubOut[8];
		EncryptBlock( pubKey, pubPlain, rgubOut );
		CHECK( BytesEqual( rgubOut, pubCipher, 8 ) );
		DecryptBlock( pubKey, pubCipher, rgubOut );
		CHECK( BytesEqual( rgubOut, pubPlain, 8 ) );

		u8 rgubKey[8];
		std::memcpy( rgubKey, pubKey, 8 );
		const IceKey_t key{ rgubKey };
		EncryptBlock( key, pubPlain, rgubOut );
		CHECK( BytesEqual( rgubOut, pubCipher, 8 ) );
	}

	// Two blocks and a tail of three bytes the buffer functions must not touch.
	u8 rgubPlain[19];
	for ( u8 ib = 0; ib < sizeof( rgubPlain ); ++ib )
		rgubPlain[ib] = ib;
	u8 rgubCipher[19];
	std::memset( rgubCipher, 0xAA, sizeof( rgubCipher ) );
	const u8 *pubKey = k_rgubIceVectors;
	EncryptBuffer( pubKey, rgubPlain, sizeof( rgubPlain ), rgubCipher );
	CHECK( rgubCipher[16] == 0xAA && rgubCipher[17] == 0xAA && rgubCipher[18] == 0xAA );
	u8 rgubBlock[8];
	EncryptBlock( pubKey, rgubPlain + 8, rgubBlock );
	CHECK( BytesEqual( rgubCipher + 8, rgubBlock, 8 ) );

	u8 rgubBack[16];
	DecryptBuffer( pubKey, rgubCipher, 16, rgubBack );
	CHECK( BytesEqual( rgubBack, rgubPlain, 16 ) );
}

struct HashInput_t
{
	const u8 *m_pub;
	u32 m_cub;
};

void TestHashes()
{
	const HashInput_t rgInputs[] = { VAC_TEST_HASH_INPUTS };
	CHECK( sizeof( rgInputs ) / sizeof( rgInputs[0] ) == k_cHashInputs );

	for ( unsigned iInput = 0; iInput < k_cHashInputs; ++iInput )
	{
		const HashInput_t &input = rgInputs[iInput];
		CHECK( crypto::hash::Crc32_t::Of( input.m_pub, input.m_cub ) == k_rgunCrc32[iInput] );
		CHECK( crypto::hash::Hash488781ED_t::Of( input.m_pub, input.m_cub ) == k_rgunHash488781ED[iInput] );
		CHECK( crypto::hash::Hash488781ED_t::Of( input.m_pub, input.m_cub, 0xCAFEBABEu ) ==
		       k_rgunHash488781EDSeeded[iInput] );
		CHECK( util::hashing::PathHashBytes( input.m_pub, input.m_cub ) == k_rgunPathHash[iInput] );

		u8 rgubDigest[16];
		crypto::hash::Md5_t::Of( input.m_pub, input.m_cub, rgubDigest );
		CHECK( BytesEqual( rgubDigest, k_rgubMd5 + iInput * 16, 16 ) );

		// The same digest when fed in pieces around the block size.
		crypto::hash::Md5_t md5;
		const u32 cubFirst = input.m_cub > 70 ? 70 : input.m_cub;
		md5.Update( input.m_pub, cubFirst );
		md5.Update( input.m_pub + cubFirst, input.m_cub - cubFirst );
		md5.Final( rgubDigest );
		CHECK( BytesEqual( rgubDigest, k_rgubMd5 + iInput * 16, 16 ) );
	}

	// Well known answers on top of the generated ones.
	CHECK( crypto::hash::Crc32_t::Of( reinterpret_cast<const u8 *>( "123456789" ), 9 ) == 0xCBF43926u );
	static_assert( crypto::hash::Crc32_t::Of( nullptr, 0 ) == 0 );

	u8 rgubDigest[16];
	crypto::hash::Md5_t::Of( reinterpret_cast<const u8 *>( "abc" ), 3, rgubDigest );
	const u8 rgubAbc[16] = { 0x90, 0x01, 0x50, 0x98, 0x3C, 0xD2, 0x4F, 0xB0,
	                         0xD6, 0x96, 0x3F, 0x7D, 0x28, 0xE1, 0x7F, 0x72 };
	CHECK( BytesEqual( rgubDigest, rgubAbc, 16 ) );

	// Final wipes the context like the original.
	crypto::hash::Md5_t md5;
	md5.Update( reinterpret_cast<const u8 *>( "abc" ), 3 );
	md5.Final( rgubDigest );
	const u8 rgubZero[sizeof( md5 )] = {};
	CHECK( BytesEqual( &md5, rgubZero, sizeof( md5 ) ) );
	md5.Init();
	md5.Update( reinterpret_cast<const u8 *>( "abc" ), 3 );
	md5.Final( rgubDigest );
	CHECK( BytesEqual( rgubDigest, rgubAbc, 16 ) );

	CHECK( util::hashing::PathHash( "kernel32.dll" ) == k_unHashKernel32 );
	CHECK( util::hashing::PathHash( "KERNEL32.DLL" ) == k_unHashKernel32 );
	CHECK( util::hashing::ServiceNameHash( "kernel32.dll" ) == k_unHashKernel32 );
	CHECK( util::hashing::ServiceNameHash( "", 0 ) == 0 );
	CHECK( util::hashing::ServiceNameHash( nullptr ) == 0 );
	CHECK( util::hashing::PathHash( nullptr ) == util::hashing::k_unHashSeed );
	CHECK( util::hashing::k_unHashSeed == 1171724434u );
}

void TestParkMiller()
{
	const unsigned cSeeds = sizeof( k_rgunParkMillerSeeds ) / sizeof( k_rgunParkMillerSeeds[0] );
	for ( unsigned iSeed = 0; iSeed < cSeeds; ++iSeed )
	{
		crypto::random::ParkMiller_t prng( k_rgunParkMillerSeeds[iSeed] );
		bool bMatches = true;
		for ( unsigned iOutput = 0; iOutput < k_cParkMillerOutputs; ++iOutput )
			bMatches &= prng.Next() == k_rgunParkMillerOutputs[iSeed * k_cParkMillerOutputs + iOutput];
		CHECK( bMatches );
	}
	static_assert( sizeof( crypto::random::ParkMiller_t ) == 8 + 32 * 4 );
}

void TestBignum()
{
	using crypto::bigint::Bignum_t;

	Bignum_t value;
	value.SetInt( 65 );
	CHECK( value.m_cUsed == 1 && value.m_cBits == 7 );

	Bignum_t exponent;
	exponent.SetInt( 17 );
	Bignum_t modulus;
	modulus.SetInt( 3233 );
	value.ModExp( exponent, modulus );
	CHECK( value.m_punData[0] == k_nRsaSmallResult );
	value.Destroy();
	exponent.Destroy();
	modulus.Destroy();

	Bignum_t n1024;
	n1024.SetBytes( k_rgubRsaN1024, sizeof( k_rgubRsaN1024 ) );
	CHECK( n1024.m_cBits == 1024 && n1024.m_cUsed == 32 );
	Bignum_t n2048;
	n2048.SetBytes( k_rgubRsaN2048, sizeof( k_rgubRsaN2048 ) );
	CHECK( n2048.m_cBits == 2048 );

	Bignum_t product;
	product.CopyFrom( n1024 );
	product.Multiply( n2048 );
	CHECK( BignumEquals( product, k_rgubRsaProduct ) );
	product.Destroy();

	Bignum_t quotient;
	quotient.CopyFrom( n2048 );
	Bignum_t remainder;
	quotient.DivMod( n1024, remainder );
	CHECK( BignumEquals( quotient, k_rgubRsaQuotient ) );
	CHECK( BignumEquals( remainder, k_rgubRsaRemainder ) );
	quotient.Destroy();
	remainder.Destroy();

	Bignum_t e65537;
	e65537.SetInt( 65537 );

	Bignum_t base;
	base.SetBytes( k_rgubRsaBase1024, sizeof( k_rgubRsaBase1024 ) );
	base.ModExp( e65537, n1024 );
	CHECK( BignumEquals( base, k_rgubRsaPow1024 ) );
	base.Destroy();

	base.SetBytes( k_rgubRsaBase1024, sizeof( k_rgubRsaBase1024 ) );
	base.ModExp( e65537, n2048 );
	CHECK( BignumEquals( base, k_rgubRsaPow2048 ) );
	base.Destroy();

	// A base more than twice the modulus takes the DivMod path in ModExp.
	Bignum_t e3;
	e3.SetInt( 3 );
	base.SetBytes( k_rgubRsaBig, sizeof( k_rgubRsaBig ) );
	CHECK( base.m_cBits > 2 * n1024.m_cBits );
	base.ModExp( e3, n1024 );
	CHECK( BignumEquals( base, k_rgubRsaPowBig ) );
	base.Destroy();

	Bignum_t shifted;
	shifted.SetInt( 0x80000000u );
	shifted.ShiftRight( 31, 0 );
	CHECK( shifted.m_cBits == 1 && shifted.m_punData[0] == 1 );
	shifted.Destroy();

	e3.Destroy();
	e65537.Destroy();
	n1024.Destroy();
	n2048.Destroy();
}

void TestRsa()
{
	using namespace crypto::rsa;

	u8 rgubOut[256];
	u32 cubOut = 64;
	ERsaError eError = static_cast<ERsaError>( 0xFFFFFFFFu );
	CHECK( EncryptSessionKey( k_rgubRsaSession, sizeof( k_rgubRsaSession ), k_rgubRsaModuleKey,
	                          sizeof( k_rgubRsaModuleKey ), rgubOut, &cubOut, &eError ) );
	CHECK( eError == ERsaError::Ok && cubOut == 64 );
	CHECK( BytesEqual( rgubOut, k_rgubRsaModuleCipher, 64 ) );

	cubOut = 128;
	CHECK( EncryptSessionKey( k_rgubRsaSession, sizeof( k_rgubRsaSession ), k_rgubRsaKey1024,
	                          sizeof( k_rgubRsaKey1024 ), rgubOut, &cubOut, &eError ) );
	CHECK( BytesEqual( rgubOut, k_rgubRsaCipher1024, 128 ) );

	// Too small a buffer reports the size it needs.
	cubOut = 64;
	CHECK( !EncryptSessionKey( k_rgubRsaSession, sizeof( k_rgubRsaSession ), k_rgubRsaKey1024,
	                           sizeof( k_rgubRsaKey1024 ), rgubOut, &cubOut, &eError ) );
	CHECK( eError == ERsaError::BufferTooSmall && cubOut >= 120 && cubOut <= 128 );

	const u8 rgubGarbage[4] = { 0x31, 0x02, 0x00, 0x00 };
	cubOut = 64;
	CHECK( !EncryptSessionKey( k_rgubRsaSession, sizeof( k_rgubRsaSession ), rgubGarbage, sizeof( rgubGarbage ),
	                           rgubOut, &cubOut, &eError ) );
	CHECK( eError == ERsaError::ParseFailed );

	cubOut = 64;
	CHECK( !EncryptSessionKey( k_rgubRsaSession, sizeof( k_rgubRsaSession ), k_rgubRsaKeyTooBig,
	                           sizeof( k_rgubRsaKeyTooBig ), rgubOut, &cubOut, &eError ) );
	CHECK( eError == ERsaError::BadKeySize );

	crypto::bigint::Bignum_t exponent;
	crypto::bigint::Bignum_t modulus;
	CHECK( ParsePublicKey( k_rgubRsaModuleKey, sizeof( k_rgubRsaModuleKey ), exponent, modulus ) );
	CHECK( modulus.m_cBits == 512 && exponent.m_punData[0] == 65537 );
	exponent.Destroy();
	modulus.Destroy();
}

void TestParseTlv()
{
	const u8 *pubValue = nullptr;
	u32 cubValue = 0;

	const u8 rgubShort[] = { 0x30, 0x03, 1, 2, 3, 0xFF };
	CHECK( util::ParseTlv( util::EAsn1Tag::Sequence, rgubShort, sizeof( rgubShort ), pubValue, cubValue ) );
	CHECK( pubValue == rgubShort + 2 && cubValue == 3 );

	CHECK( !util::ParseTlv( util::EAsn1Tag::Integer, rgubShort, sizeof( rgubShort ), pubValue, cubValue ) );
	CHECK( pubValue == nullptr && cubValue == 0 );

	const u8 rgubTruncated[] = { 0x30, 0x05, 1, 2 };
	CHECK( !util::ParseTlv( util::EAsn1Tag::Sequence, rgubTruncated, sizeof( rgubTruncated ), pubValue, cubValue ) );

	std::vector<u8> rgubLong = { 0x04, 0x81, 0x80 };
	rgubLong.resize( 3 + 0x80 );
	CHECK( util::ParseTlv( util::EAsn1Tag::OctetString, rgubLong.data(), u32( rgubLong.size() ), pubValue, cubValue ) );
	CHECK( pubValue == rgubLong.data() + 3 && cubValue == 0x80 );

	const u8 rgubFiveLengthBytes[] = { 0x04, 0x85, 0, 0, 0, 0, 1, 9 };
	CHECK( !util::ParseTlv( util::EAsn1Tag::OctetString, rgubFiveLengthBytes, sizeof( rgubFiveLengthBytes ), pubValue,
	                        cubValue ) );

	const u8 rgubWrap[] = { 0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0 };
	CHECK( !util::ParseTlv( util::EAsn1Tag::OctetString, rgubWrap, sizeof( rgubWrap ), pubValue, cubValue ) );

	CHECK( !util::ParseTlv( util::EAsn1Tag::OctetString, rgubWrap, 1, pubValue, cubValue ) );
}

void TestStrings()
{
	CHECK( util::StrLenA( "abc" ) == 3 && util::StrLenA( nullptr ) == 0 );
	CHECK( util::StrLenW( L"abcd" ) == 4 && util::StrLenW( nullptr ) == 0 );
	CHECK( util::EqualA( "abc", "abc" ) && !util::EqualA( "abc", "abd" ) && !util::EqualA( "abc", "ab" ) );
	CHECK( std::strcmp( util::BasenameA( "c:\\x/y\\file.dll" ), "file.dll" ) == 0 );
	CHECK( std::strcmp( util::BasenameA( "file.dll" ), "file.dll" ) == 0 );

	char szOut[5];
	std::memset( szOut, 0x7F, sizeof( szOut ) );
	util::CopyA( szOut, "abcdefgh", sizeof( szOut ) );
	CHECK( std::strcmp( szOut, "abcd" ) == 0 );
	util::CopyA( szOut, nullptr, sizeof( szOut ) );
	CHECK( szOut[0] == 0 );
	szOut[0] = 'x';
	util::CopyA( szOut, "abc", 0 );
	CHECK( szOut[0] == 'x' );

	const u8 rgubRaw[9] = { 0xAA, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	CHECK( util::Read32( rgubRaw + 1 ) == 0x04030201u );
	CHECK( util::Read64( rgubRaw + 1 ) == 0x0807060504030201ull );
	u8 rgubWrite[3] = {};
	util::Write16( rgubWrite + 1, 0xBEEF );
	CHECK( rgubWrite[0] == 0 && rgubWrite[1] == 0xEF && rgubWrite[2] == 0xBE );

	CHECK( util::AlignUp( 7, 4 ) == 8 && util::AlignUp( 8, 4 ) == 8 && util::AlignUp( 0, 4 ) == 0 );
	CHECK( util::AlignUp( 5, 0 ) == 5 && util::AlignUp( 0x1001, 0x1000 ) == 0x2000 );

	static_assert( util::MapProtectionFlags( util::EProtectMode::NoAccess ) == PAGE_NOACCESS );
	static_assert( util::MapProtectionFlags( util::EProtectMode::ReadOnly ) == PAGE_READONLY );
	static_assert( util::MapProtectionFlags( util::EProtectMode::ReadWrite ) == PAGE_READWRITE );
	static_assert( util::MapProtectionFlags( util::EProtectMode::Execute ) == PAGE_EXECUTE );
	static_assert( util::MapProtectionFlags( util::EProtectMode::ExecuteRead ) == PAGE_EXECUTE_READ );
	static_assert( util::MapProtectionFlags( util::EProtectMode::ExecuteReadWrite ) == PAGE_EXECUTE_READWRITE );
	static_assert( util::MapProtectionFlags( static_cast<util::EProtectMode>( 0b010 ) ) == 0xFFFFFFFFu );
	static_assert( util::MapProtectionFlags( static_cast<util::EProtectMode>( 0b110 ) ) == 0xFFFFFFFFu );
	CHECK( util::MapProtectionFlags( util::EProtectMode::ReadWrite ) == PAGE_READWRITE );

	CHECK( static_cast<u32>( STATUS_INFO_LENGTH_MISMATCH ) == 0xC0000004u &&
	       static_cast<u32>( STATUS_ACCESS_DENIED ) == 0xC0000022u );
	CHECK( static_cast<u32>( STATUS_BUFFER_TOO_SMALL ) == 0xC0000023u &&
	       static_cast<u32>( STATUS_NO_MORE_ENTRIES ) == 0x8000001Au );

	using namespace util::wstr;
	CHECK( Length( L"abc" ) == 3 && Length( nullptr ) == 0 );

	wchar_t wszOut[5];
	Copy( wszOut, L"abcdefgh", 5 );
	CHECK( std::wcscmp( wszOut, L"abcd" ) == 0 );
	Copy( wszOut, nullptr, 5 );
	CHECK( wszOut[0] == 0 );
	Copy( wszOut, L"ab", 5 );
	Cat( wszOut, L"cdefg", 5 );
	CHECK( std::wcscmp( wszOut, L"abcd" ) == 0 );

	CHECK( PrefixEqualI( L"C:\\WINDOWS", L"c:\\windows\\system32", 10 ) );
	CHECK( !PrefixEqualI( L"C:\\WINDOWS", L"c:\\winnt", 8 ) );
	CHECK( PrefixEqualI( L"ab", L"AB", 10 ) );

	// As the original: the first char is never looked at.
	CHECK( std::wcscmp( BaseName( L"c:\\dir\\file.dll" ), L"file.dll" ) == 0 );
	CHECK( std::wcscmp( BaseName( L"file.dll" ), L"file.dll" ) == 0 );
	CHECK( std::wcscmp( BaseName( L"\\file.dll" ), L"\\file.dll" ) == 0 );
	CHECK( std::wcscmp( BaseName( L"\\" ), L"\\" ) == 0 );
	CHECK( std::wcscmp( BaseName( L"a\\" ), L"" ) == 0 );
	CHECK( BaseName( nullptr ) == nullptr );

	auto szXor = util::MakeXorString<0x13>( "kernel32.dll" );
	CHECK( BytesEqual( &szXor, k_rgubXorKernel32, sizeof( k_rgubXorKernel32 ) ) );
	szXor.Decode();
	CHECK( std::strcmp( szXor.Get(), "kernel32.dll" ) == 0 );

	auto wszXor = util::MakeXorString<0x13>( L"Directory" );
	CHECK( static_cast<unsigned>( wszXor.Get()[0] ) == k_unXorWideFirst );
	wszXor.Decode();
	CHECK( std::wcscmp( wszXor.Get(), L"Directory" ) == 0 );
}

DWORD WINAPI FakeGetLastError()
{
	return 0x1234;
}

void TestEncoding()
{
	SystemImports_t imports{};
	CHECK( util::GetLastError( nullptr ) == 0 );
	CHECK( util::GetLastError( &imports ) == 0 );
	imports.GetLastError = FakeGetLastError;
	CHECK( util::GetLastError( &imports ) == 0x1234 );

	char szOut[8];
	std::memset( szOut, 0x7F, sizeof( szOut ) );
	util::encoding::WideToUtf8( &imports, L"abc", szOut, sizeof( szOut ) );
	CHECK( szOut[0] == 0 );

	imports.WideCharToMultiByte = ::WideCharToMultiByte;
	imports.MultiByteToWideChar = ::MultiByteToWideChar;

	std::memset( szOut, 0x7F, sizeof( szOut ) );
	util::encoding::WideToUtf8( &imports, L"ab\x00E9", szOut, sizeof( szOut ) );
	CHECK( std::strcmp( szOut, "ab\xC3\xA9" ) == 0 );
	CHECK( szOut[7] == 0 );

	wchar_t wszOut[8];
	util::encoding::Utf8ToWide( &imports, "ab\xC3\xA9", wszOut, 8 );
	CHECK( std::wcscmp( wszOut, L"ab\x00E9" ) == 0 );

	// The original's converter leaves the tail alone on success and only cuts on failure.
	std::memset( szOut, 0x7F, sizeof( szOut ) );
	CHECK( util::encoding::WideToUtf8Bounded( &imports, L"abc", szOut, sizeof( szOut ) ) == 4 );
	CHECK( std::strcmp( szOut, "abc" ) == 0 && szOut[7] == 0x7F );

	std::memset( szOut, 0x7F, sizeof( szOut ) );
	CHECK( util::encoding::WideToUtf8Bounded( &imports, L"abcdefghijkl", szOut, sizeof( szOut ) ) == 0 );
	CHECK( szOut[7] == 0 );
}

void TestLayouts()
{
	// Checked against the Windows SDK's own view of the same structures.
	CHECK( offsetof( nt::Peb32_t, m_ulLdr ) == offsetof( PEB, Ldr ) );
	CHECK( offsetof( nt::Peb32_t, m_ulProcessParameters ) == offsetof( PEB, ProcessParameters ) );
	CHECK( offsetof( nt::Peb32_t, m_bBeingDebugged ) == offsetof( PEB, BeingDebugged ) );
	CHECK( offsetof( nt::PebLdrData32_t, m_InMemoryOrderModuleList ) ==
	       offsetof( PEB_LDR_DATA, InMemoryOrderModuleList ) );
	CHECK( offsetof( nt::LdrDataTableEntry32_t, m_InMemoryOrderLinks ) ==
	       offsetof( LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks ) );
	CHECK( offsetof( nt::LdrDataTableEntry32_t, m_ulDllBase ) == offsetof( LDR_DATA_TABLE_ENTRY, DllBase ) );
	CHECK( offsetof( nt::LdrDataTableEntry32_t, m_FullDllName ) == offsetof( LDR_DATA_TABLE_ENTRY, FullDllName ) );
	CHECK( offsetof( nt::ProcessParameters32_t, m_ImagePathName ) ==
	       offsetof( RTL_USER_PROCESS_PARAMETERS, ImagePathName ) );
	CHECK( offsetof( nt::ProcessParameters32_t, m_CommandLine ) ==
	       offsetof( RTL_USER_PROCESS_PARAMETERS, CommandLine ) );
	CHECK( sizeof( nt::ProcessBasicInformation32_t ) == sizeof( PROCESS_BASIC_INFORMATION ) );
	CHECK( sizeof( nt::UnicodeString32_t ) == sizeof( UNICODE_STRING ) );

	CHECK( offsetof( nt::Peb32_t, m_ulLdr ) == 0x0C && offsetof( nt::Peb32_t, m_ulProcessParameters ) == 0x10 );
	CHECK( offsetof( nt::Peb64_t, m_ulLdr ) == 0x18 && offsetof( nt::Peb64_t, m_ulProcessParameters ) == 0x20 );
	CHECK( sizeof( nt::Peb32_t ) == 468 && sizeof( nt::Peb64_t ) == 320 );
	CHECK( sizeof( nt::PebLdrData64_t ) == 88 );
	CHECK( offsetof( nt::LdrDataTableEntry64_t, m_rgubRest ) + sizeof( nt::LdrDataTableEntry64_t::m_rgubRest ) == 140 );
	CHECK( sizeof( nt::LdrDataTableEntry32_t ) == 72 );
	CHECK( sizeof( nt::ObjectDirectoryEntry_t ) == 16 );

	// The structures against this very process.
	const auto *pPeb = reinterpret_cast<const nt::Peb32_t *>( __readfsdword( 0x30 ) );
	CHECK( pPeb->m_ulImageBaseAddress == reinterpret_cast<u32>( GetModuleHandleW( nullptr ) ) );
	CHECK( pPeb->m_bBeingDebugged == static_cast<u8>( IsDebuggerPresent() ) );

	const auto *pLdr = reinterpret_cast<const nt::PebLdrData32_t *>( pPeb->m_ulLdr );
	const auto *pFirst = reinterpret_cast<const nt::LdrDataTableEntry32_t *>( pLdr->m_InLoadOrderModuleList.m_ulFlink );
	CHECK( pFirst->m_ulDllBase == pPeb->m_ulImageBaseAddress );
	const auto *pwszBase = reinterpret_cast<const wchar_t *>( pFirst->m_BaseDllName.m_ulBuffer );
	CHECK( pFirst->m_BaseDllName.m_cubLength == 2 * std::wcslen( L"sdk_tests.exe" ) );
	CHECK( _wcsnicmp( pwszBase, L"sdk_tests.exe", 13 ) == 0 );

	const auto *pParameters = reinterpret_cast<const nt::ProcessParameters32_t *>( pPeb->m_ulProcessParameters );
	CHECK( pParameters->m_ImagePathName.m_cubLength > 0 );
	CHECK( std::wstring( reinterpret_cast<const wchar_t *>( pParameters->m_CommandLine.m_ulBuffer ),
	                     pParameters->m_CommandLine.m_cubLength / 2 ) == GetCommandLineW() );

	const volatile nt::KUserSharedData_t &kuser = nt::GetKUserSharedData();
	CHECK( kuser.m_unTickCountMultiplier != 0 );
	FILETIME now;
	GetSystemTimeAsFileTime( &now );
	const i32 nHigh = kuser.m_SystemTime.m_nHigh1Time;
	CHECK( static_cast<u32>( nHigh ) == now.dwHighDateTime || static_cast<u32>( nHigh ) + 1 == now.dwHighDateTime );

	CHECK( sizeof( VacInputPacket_t ) == 0xB0 && sizeof( VacOutputPacket_t ) == 0x1088 );
	CHECK( sizeof( Module_t ) == 0x34 );
	CHECK( sizeof( SystemImports_t ) == 200 * sizeof( void * ) );
	CHECK( sizeof( crypto::hash::Md5_t ) == 0x58 );
	CHECK( sizeof( verify::CertIdentity_t ) == 60 && sizeof( verify::CertContextSet_t ) == 28 );
}

IMAGE_SECTION_HEADER MakeSection( const char *pszName, u32 unVirtualSize, u32 unVa, u32 cubRaw, u32 ibRaw, u32 unFlags )
{
	IMAGE_SECTION_HEADER section{};
	std::memcpy( section.Name, pszName, std::strlen( pszName ) );
	section.Misc.VirtualSize = unVirtualSize;
	section.VirtualAddress = unVa;
	section.SizeOfRawData = cubRaw;
	section.PointerToRawData = ibRaw;
	section.Characteristics = unFlags;
	return section;
}

template <usize cubImage, usize cubDigests, usize cParams>
void CheckImage( const u8 ( &rgubImage )[cubImage], const u8 ( &rgubDigests )[cubDigests],
                 const NormalizedParams_t ( &rgParams )[cParams] )
{
	CHECK( cubDigests == cParams * 16 );
	for ( usize iParams = 0; iParams < cParams; ++iParams )
	{
		const pe::NormalizedHashParams_t params{ rgParams[iParams].m_unLoadedBase32,
		                                         rgParams[iParams].m_bAppendOverlaySection };
		u8 rgubDigest[16] = {};
		CHECK( pe::HashNormalizedPeImage( rgubImage, cubImage, rgubDigest, params ) );
		CHECK( BytesEqual( rgubDigest, rgubDigests + iParams * 16, 16 ) );
	}
}

void TestPe()
{
	CheckImage( k_rgubPe32, k_rgubPe32Digests, k_rgPe32Params );
	CheckImage( k_rgubPe32OverlayReloc, k_rgubPe32OverlayRelocDigests, k_rgPe32OverlayRelocParams );
	CheckImage( k_rgubPe64, k_rgubPe64Digests, k_rgPe64Params );
	CheckImage( k_rgubPe32Largest, k_rgubPe32LargestDigests, k_rgPe32LargestParams );

	// The overlay parameter changes the answer only when something reaches the overlay.
	CHECK( !BytesEqual( k_rgubPe32OverlayRelocDigests, k_rgubPe32OverlayRelocDigests + 16, 16 ) );
	CHECK( BytesEqual( k_rgubPe32Digests, k_rgubPe32Digests + 16, 16 ) );
	CHECK( !BytesEqual( k_rgubPe32Digests, k_rgubPe32Digests + 32, 16 ) );

	const pe::NormalizedHashParams_t params{ 0, false };
	u8 rgubDigest[16];
	CHECK( !pe::HashNormalizedPeImage( nullptr, 100, rgubDigest, params ) );
	CHECK( !pe::HashNormalizedPeImage( k_rgubPe32, 0x20, rgubDigest, params ) );
	CHECK( !pe::HashNormalizedPeImage( k_rgubPe32, 0x60, rgubDigest, params ) );

	std::vector<u8> rgubBroken( k_rgubPe32, k_rgubPe32 + sizeof( k_rgubPe32 ) );
	rgubBroken[0] = 'X';
	CHECK( !pe::HashNormalizedPeImage( rgubBroken.data(), u32( rgubBroken.size() ), rgubDigest, params ) );

	// A 4 byte block size in the relocation table is corrupt.
	rgubBroken.assign( k_rgubPe32, k_rgubPe32 + sizeof( k_rgubPe32 ) );
	const IMAGE_NT_HEADERS32 &headers = *reinterpret_cast<const IMAGE_NT_HEADERS32 *>( rgubBroken.data() + 0x40 );
	const IMAGE_SECTION_HEADER *pSections = IMAGE_FIRST_SECTION( &headers );
	const u32 ibReloc = pSections[2].PointerToRawData;
	const u32 unBadSize = 4;
	std::memcpy( rgubBroken.data() + ibReloc + 4, &unBadSize, 4 );
	CHECK( !pe::HashNormalizedPeImage( rgubBroken.data(), u32( rgubBroken.size() ), rgubDigest, params ) );

	IMAGE_SECTION_HEADER rgSections[4];
	rgSections[0] = MakeSection( ".text", 0x800, 0x1000, 0x400, 0x400, IMAGE_SCN_MEM_EXECUTE );
	rgSections[1] = MakeSection( ".bss", 0x1000, 0x2000, 0, 0, 0 );
	rgSections[2] = MakeSection( ".data", 0x100, 0x3000, 0x200, 0x800, 0 );

	CHECK( pe::RvaToFileOffset( rgSections, 3, 0x1010 ) == 0x410 );
	CHECK( pe::RvaToFileOffset( rgSections, 3, 0x1400 ) == pe::k_unInvalidOffset );
	CHECK( pe::RvaToFileOffset( rgSections, 3, 0x31FF ) == 0x9FF );
	u32 ibOffset = 0;
	CHECK( pe::RvaToFileOffsetLargestSpan( rgSections, 3, 0x1400, &ibOffset ) && ibOffset == 0x800 );
	CHECK( pe::RvaToFileOffsetLargestSpan( rgSections, 3, 0x31FF, &ibOffset ) && ibOffset == 0x9FF );
	CHECK( !pe::RvaToFileOffsetLargestSpan( rgSections, 3, 0x1800, &ibOffset ) );

	CHECK( pe::FindSectionByRva( rgSections, 3, 0x17FF ) == &rgSections[0] );
	CHECK( pe::FindSectionByRva( rgSections, 3, 0x2000 ) == nullptr );
	CHECK( pe::FindSectionByRva( rgSections, 3, 0x30FF ) == &rgSections[2] );
	CHECK( pe::FindSectionByRva( rgSections, 3, 0x3100 ) == nullptr );

	pe::RangePair_t ranges;
	pe::SplitAroundDirectory( 0x1100, 0x20, 0x1000, 0x2000, ranges );
	CHECK( ranges.m_rgunStart[0] == 0x1000 && ranges.m_rgunEnd[0] == 0x1100 );
	CHECK( ranges.m_rgunStart[1] == 0x1124 && ranges.m_rgunEnd[1] == 0x2000 );

	pe::SplitAroundDirectory( 0x800, 0x820, 0x1000, 0x2000, ranges );
	CHECK( ranges.m_rgunStart[0] == 0x1024 && ranges.m_rgunEnd[0] == 0x2000 && ranges.m_rgunStart[1] == 0 );

	pe::SplitAroundDirectory( 0x1F00, 0x1000, 0x1000, 0x2000, ranges );
	CHECK( ranges.m_rgunStart[0] == 0x1000 && ranges.m_rgunEnd[0] == 0x1F00 && ranges.m_rgunStart[1] == 0 );

	pe::SplitAroundDirectory( 0x3000, 0x10, 0x1000, 0x2000, ranges );
	CHECK( ranges.m_rgunStart[0] == 0x1000 && ranges.m_rgunEnd[0] == 0x2000 && ranges.m_rgunEnd[1] == 0 );

	pe::SplitAroundDirectory( 0x800, 0x10000, 0x1000, 0x2000, ranges );
	CHECK( ranges.m_rgunStart[0] == 0 && ranges.m_rgunEnd[0] == 0 && ranges.m_rgunEnd[1] == 0 );

	// The sum wraps below the start, and like in the original nothing gets cut then.
	pe::SplitAroundDirectory( 0x800, 0xFFFFF8FCu, 0x1000, 0x2000, ranges );
	CHECK( ranges.m_rgunStart[0] == 0x1000 && ranges.m_rgunEnd[0] == 0x2000 && ranges.m_rgunEnd[1] == 0 );
	pe::SplitAroundDirectory( 0x1800, 0xFFFFF8FCu, 0x1000, 0x2000, ranges );
	CHECK( ranges.m_rgunStart[0] == 0x1000 && ranges.m_rgunEnd[0] == 0x2000 && ranges.m_rgunEnd[1] == 0 );

	CHECK( pe::SelectHashSection( rgSections, 3 ) == &rgSections[0] );
	rgSections[3] = MakeSection( ".text2", 0x100, 0x4000, 0x100, 0xA00, IMAGE_SCN_MEM_EXECUTE );
	CHECK( pe::SelectHashSection( rgSections, 4 ) == &rgSections[3] );
	IMAGE_SECTION_HEADER rgPlain[2];
	rgPlain[0] = MakeSection( "A", 0, 0, 0x100, 1, IMAGE_SCN_MEM_EXECUTE );
	rgPlain[1] = MakeSection( "B", 0, 0, 0x300, 2, IMAGE_SCN_MEM_EXECUTE );
	CHECK( pe::SelectHashSection( rgPlain, 2 ) == &rgPlain[1] );
	rgPlain[1].Characteristics = 0;
	CHECK( pe::SelectHashSection( rgPlain, 2 ) == &rgPlain[0] );
	rgPlain[0].Characteristics = 0;
	CHECK( pe::SelectHashSection( rgPlain, 2 ) == nullptr );

	IMAGE_SECTION_HEADER rgOverlay[3];
	rgOverlay[0] = MakeSection( ".text", 0x500, 0x1000, 0x400, 0x400, 0 );
	u32 cSections = 1;
	CHECK( pe::AppendOverlaySection( rgOverlay, &cSections, 0x800, 0x1000 ) && cSections == 1 );
	CHECK( pe::AppendOverlaySection( rgOverlay, &cSections, 0x900, 0x1000 ) && cSections == 2 );
	CHECK( std::memcmp( rgOverlay[1].Name, ".extra\0\0", 8 ) == 0 );
	CHECK( rgOverlay[1].PointerToRawData == 0x800 && rgOverlay[1].SizeOfRawData == 0x100 );
	CHECK( rgOverlay[1].VirtualAddress == 0x2000 && rgOverlay[1].Misc.VirtualSize == 0x1000 );
	CHECK( rgOverlay[1].Characteristics == 0x02000000u );
	cSections = 1;
	CHECK( !pe::AppendOverlaySection( rgOverlay, &cSections, 0x900, 0 ) );

	// A raw size above the virtual size rounds up before the next address is computed.
	rgOverlay[0] = MakeSection( ".text", 0x100, 0x1000, 0x1400, 0x400, 0 );
	CHECK( pe::AppendOverlaySection( rgOverlay, &cSections, 0x2000, 0x1000 ) && cSections == 2 );
	CHECK( rgOverlay[1].VirtualAddress == 0x3000 );

	IMAGE_OPTIONAL_HEADER32 optional32{};
	optional32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0x1234;
	CHECK( pe::GetDataDirectory( &optional32, false, IMAGE_DIRECTORY_ENTRY_IAT )->VirtualAddress == 0x1234 );
	IMAGE_OPTIONAL_HEADER64 optional64{};
	optional64.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0x4321;
	CHECK( pe::GetDataDirectory( &optional64, true, IMAGE_DIRECTORY_ENTRY_BASERELOC )->Size == 0x4321 );
}

// Written from the LZ4 block format description, not from the compressor.
bool DecodeLz4( const u8 *pubIn, int cubIn, std::vector<u8> &rgubOut )
{
	const u8 *pubEnd = pubIn + cubIn;
	while ( pubIn < pubEnd )
	{
		const u8 unToken = *pubIn++;
		usize cubLiterals = unToken >> 4;
		if ( cubLiterals == 15 )
		{
			u8 unMore;
			do
			{
				unMore = *pubIn++;
				cubLiterals += unMore;
			} while ( unMore == 255 );
		}
		rgubOut.insert( rgubOut.end(), pubIn, pubIn + cubLiterals );
		pubIn += cubLiterals;
		if ( pubIn >= pubEnd )
			return pubIn == pubEnd;

		const usize cubOffset = pubIn[0] | ( pubIn[1] << 8 );
		pubIn += 2;
		usize cubMatch = unToken & 15;
		if ( cubMatch == 15 )
		{
			u8 unMore;
			do
			{
				unMore = *pubIn++;
				cubMatch += unMore;
			} while ( unMore == 255 );
		}
		cubMatch += 4;
		if ( !cubOffset || cubOffset > rgubOut.size() )
			return false;
		for ( usize ib = 0; ib < cubMatch; ++ib )
			rgubOut.push_back( rgubOut[rgubOut.size() - cubOffset] );
	}
	return true;
}

void TestLz4()
{
	using namespace compress::lz4;

	CHECK( CompressBound( 0 ) == 16 && CompressBound( 255 ) == 255 + 1 + 16 );
	CHECK( CompressBound( k_cubMaxInput + 1 ) == 0 );
	CHECK( CommonBytes( 0 ) == 4 && CommonBytes( 1 ) == 0 && CommonBytes( 0x0100 ) == 1 &&
	       CommonBytes( 0x01000000 ) == 3 );

	u8 rgubIn[32] = {};
	u8 rgubOut[128];
	CHECK( Compress( rgubIn, rgubOut, 0, sizeof( rgubOut ) ) == 0 );
	CHECK( Compress( rgubIn, rgubOut, 32, 10 ) == 0 );

	// Under 13 bytes everything is one literal run, by the format.
	const char rgchAbc[] = "abcdefghijkl";
	CHECK( Compress( reinterpret_cast<const u8 *>( rgchAbc ), rgubOut, 12, sizeof( rgubOut ) ) == 13 );
	CHECK( rgubOut[0] == 0xC0 && BytesEqual( rgubOut + 1, rgchAbc, 12 ) );

	// Same output as the module's own copy, across every kind of input.
	std::mt19937 rng( 0x5AFE1234u );
	int cCases = 0;
	int cDifferent = 0;
	int cBadRoundTrips = 0;
	for ( int iRound = 0; iRound < 3000; ++iRound )
	{
		std::vector<u8> rgubInput( rng() % 60000 + 1 );
		const int nMode = rng() % 5;
		const unsigned cAlphabet = nMode == 0 ? 1 : nMode == 1 ? 4 : nMode == 2 ? 16 : nMode == 3 ? 64 : 256;
		u8 unLast = 0;
		for ( u8 &unByte : rgubInput )
		{
			unByte = ( nMode == 1 && rng() % 20 ) ? unLast : static_cast<u8>( rng() % cAlphabet );
			unLast = unByte;
		}
		if ( rng() % 4 == 0 )
		{
			const usize ibHalf = rgubInput.size() / 2;
			for ( usize ib = ibHalf; ib < rgubInput.size(); ++ib )
				rgubInput[ib] = rgubInput[ib - ibHalf];
		}

		const u32 cubInput = u32( rgubInput.size() );
		const u32 cubBound = reference::lz4CompressBound( cubInput );
		std::vector<u8> rgubExpected( cubBound + 8, 0xCC );
		std::vector<u8> rgubActual( cubBound + 8, 0xCC );
		const int cubExpected = reference::lz4Compress( rgubInput.data(), rgubExpected.data(), cubInput, cubBound );
		const int cubActual = Compress( rgubInput.data(), rgubActual.data(), cubInput, cubBound );
		++cCases;
		if ( cubExpected != cubActual || rgubExpected != rgubActual )
			++cDifferent;

		std::vector<u8> rgubDecoded;
		if ( !DecodeLz4( rgubActual.data(), cubActual, rgubDecoded ) || rgubDecoded != rgubInput )
			++cBadRoundTrips;
	}
	std::printf( "lz4: %d random inputs, %d differ from the module copy, %d bad round trips\n", cCases, cDifferent,
	             cBadRoundTrips );
	CHECK( cDifferent == 0 );
	CHECK( cBadRoundTrips == 0 );
}

struct FakeFile_t
{
	std::vector<u8> m_rgubData;
	usize m_ibCursor = 0;
	u32 m_cReads = 0;
	u32 m_cubLargestRead = 0;
	bool m_bFailReads = false;
	bool m_bLargeFile = false;
};
FakeFile_t g_File;

BOOL WINAPI FakeGetFileSizeEx( HANDLE, PLARGE_INTEGER pSize )
{
	pSize->QuadPart = static_cast<LONGLONG>( g_File.m_rgubData.size() ) + ( g_File.m_bLargeFile ? 0x100000000ll : 0 );
	return TRUE;
}

DWORD WINAPI FakeGetFileSize( HANDLE, LPDWORD punHigh )
{
	if ( punHigh )
		*punHigh = g_File.m_bLargeFile ? 1 : 0;
	return static_cast<DWORD>( g_File.m_rgubData.size() );
}

BOOL WINAPI FakeReadFile( HANDLE, LPVOID pBuffer, DWORD cubWanted, LPDWORD pcubRead, LPOVERLAPPED )
{
	if ( g_File.m_bFailReads )
		return FALSE;
	const usize cubLeft = g_File.m_rgubData.size() - g_File.m_ibCursor;
	const DWORD cub = cubWanted < cubLeft ? cubWanted : static_cast<DWORD>( cubLeft );
	std::memcpy( pBuffer, g_File.m_rgubData.data() + g_File.m_ibCursor, cub );
	g_File.m_ibCursor += cub;
	*pcubRead = cub;
	++g_File.m_cReads;
	if ( cubWanted > g_File.m_cubLargestRead )
		g_File.m_cubLargestRead = cubWanted;
	return TRUE;
}

void TestFileSizeAndRead()
{
	SystemImports_t imports{};
	u32 cubSize = 0xFFFFFFFFu;
	CHECK( !file::GetFileSize32( nullptr, nullptr, &cubSize ) && cubSize == 0 );
	CHECK( !file::GetFileSize32( &imports, nullptr, &cubSize ) );

	g_File = {};
	g_File.m_rgubData.resize( 0x25000 );
	for ( usize ib = 0; ib < g_File.m_rgubData.size(); ++ib )
		g_File.m_rgubData[ib] = static_cast<u8>( ib * 13 );

	imports.GetFileSize = FakeGetFileSize;
	CHECK( file::GetFileSize32( &imports, nullptr, &cubSize ) && cubSize == 0x25000 );
	CHECK( file::GetFileSizeOrZero( &imports, nullptr ) == 0x25000 );
	CHECK( file::GetFileSizeOrZero( &imports, INVALID_HANDLE_VALUE ) == 0 );
	g_File.m_bLargeFile = true;
	CHECK( !file::GetFileSize32( &imports, nullptr, &cubSize ) );
	imports.GetFileSizeEx = FakeGetFileSizeEx;
	CHECK( !file::GetFileSize32( &imports, nullptr, &cubSize ) );
	g_File.m_bLargeFile = false;
	CHECK( file::GetFileSize32( &imports, nullptr, &cubSize ) && cubSize == 0x25000 );

	u8 *pubData = nullptr;
	u32 cubData = 0;
	CHECK( !file::ReadWholeFile( nullptr, nullptr, &pubData, &cubData, true ) );
	CHECK( !file::ReadWholeFile( &imports, nullptr, &pubData, &cubData, true ) );

	imports.ReadFile = FakeReadFile;

	// Without the fallback the heap imports are required, as in process_memory_map.
	CHECK( !file::ReadWholeFile( &imports, nullptr, &pubData, &cubData, false ) );

	// With it the linked kernel32 steps in, as in driver_inventory.
	CHECK( file::ReadWholeFile( &imports, nullptr, &pubData, &cubData, true ) );
	CHECK( cubData == 0x25000 && BytesEqual( pubData, g_File.m_rgubData.data(), cubData ) );
	CHECK( g_File.m_cReads == 3 && g_File.m_cubLargestRead == 0x10000u );
	file::FreeWholeFile( &imports, pubData, true );

	imports.HeapAlloc = ::HeapAlloc;
	imports.HeapFree = ::HeapFree;
	imports.GetProcessHeap = ::GetProcessHeap;
	g_File.m_ibCursor = 0;
	CHECK( file::ReadWholeFile( &imports, nullptr, &pubData, &cubData, false ) );
	CHECK( BytesEqual( pubData, g_File.m_rgubData.data(), cubData ) );
	file::FreeWholeFile( &imports, pubData, false );

	g_File.m_bFailReads = true;
	CHECK( !file::ReadWholeFile( &imports, nullptr, &pubData, &cubData, false ) && pubData == nullptr );
	g_File.m_bFailReads = false;
	g_File.m_rgubData.clear();
	CHECK( !file::ReadWholeFile( &imports, nullptr, &pubData, &cubData, false ) );
}

struct FakeVolumes_t
{
	u32 m_cVolumes = 2;
	u32 m_iVolume = 0;
	bool m_bFindFails = false;
	bool m_bRootFails = false;
	bool m_bOpenFails = false;
	std::wstring m_wstrRootOpened;
	DWORD m_unAccess = 0;
	DWORD m_unShare = 0;
	DWORD m_unFlags = 0;
	LONGLONG m_nFileId = 0;
	FILE_ID_TYPE m_eType = MaximumFileIdType;
	u32 m_cRootsClosed = 0;
	u32 m_cFindsClosed = 0;
};
FakeVolumes_t g_Volumes;
constexpr u32 k_unFakeSerialSecond = 0xBEEF0002;

HANDLE WINAPI FakeFindFirstVolumeW( LPWSTR pwszVolume, DWORD )
{
	if ( g_Volumes.m_bFindFails )
		return INVALID_HANDLE_VALUE;
	wcscpy_s( pwszVolume, 260, L"\\\\?\\Volume{0}\\" );
	return reinterpret_cast<HANDLE>( 0x70 );
}

BOOL WINAPI FakeFindNextVolumeW( HANDLE, LPWSTR pwszVolume, DWORD )
{
	if ( ++g_Volumes.m_iVolume >= g_Volumes.m_cVolumes )
		return FALSE;
	wcscpy_s( pwszVolume, 260, L"\\\\?\\Volume{1}\\" );
	return TRUE;
}

BOOL WINAPI FakeFindVolumeClose( HANDLE )
{
	++g_Volumes.m_cFindsClosed;
	return TRUE;
}

BOOL WINAPI FakeGetVolumeInformationW( LPCWSTR, LPWSTR, DWORD, LPDWORD punSerial, LPDWORD, LPDWORD, LPWSTR, DWORD )
{
	*punSerial = g_Volumes.m_iVolume == 1 ? k_unFakeSerialSecond : 0x1111;
	return TRUE;
}

HANDLE WINAPI FakeCreateFileW( LPCWSTR pwszPath, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE )
{
	g_Volumes.m_wstrRootOpened = pwszPath;
	return g_Volumes.m_bRootFails ? INVALID_HANDLE_VALUE : reinterpret_cast<HANDLE>( 0x80 );
}

HANDLE WINAPI FakeOpenFileById( HANDLE, LPFILE_ID_DESCRIPTOR pDescriptor, DWORD unAccess, DWORD unShare,
                                LPSECURITY_ATTRIBUTES, DWORD unFlags )
{
	g_Volumes.m_unAccess = unAccess;
	g_Volumes.m_unShare = unShare;
	g_Volumes.m_unFlags = unFlags;
	g_Volumes.m_nFileId = pDescriptor->FileId.QuadPart;
	g_Volumes.m_eType = pDescriptor->Type;
	return g_Volumes.m_bOpenFails ? INVALID_HANDLE_VALUE : reinterpret_cast<HANDLE>( 0x90 );
}

BOOL WINAPI FakeCloseRoot( HANDLE )
{
	++g_Volumes.m_cRootsClosed;
	return TRUE;
}

void TestOpenById()
{
	using file::EOpenByIdStatus;

	HANDLE hFile = nullptr;
	u32 unLastError = 77;
	SystemImports_t imports{};
	CHECK( file::OpenByVolumeAndId( &imports, 0, 0, 0, &hFile, &unLastError ) == EOpenByIdStatus::ImportsMissing );
	CHECK( hFile == INVALID_HANDLE_VALUE && unLastError == 0 );

	imports.FindFirstVolumeW = FakeFindFirstVolumeW;
	imports.FindNextVolumeW = FakeFindNextVolumeW;
	imports.FindVolumeClose = FakeFindVolumeClose;
	imports.GetVolumeInformationW = FakeGetVolumeInformationW;
	imports.CreateFileW = FakeCreateFileW;
	imports.OpenFileById = FakeOpenFileById;
	imports.CloseHandle = FakeCloseRoot;
	imports.GetLastError = FakeGetLastError;

	g_Volumes = {};
	CHECK( file::OpenByVolumeAndId( &imports, k_unFakeSerialSecond, 0x1122334455667788ull, FILE_GENERIC_READ, &hFile,
	                                &unLastError ) == EOpenByIdStatus::Ok );
	CHECK( hFile == reinterpret_cast<HANDLE>( 0x90 ) && unLastError == 0x1234 );
	CHECK( g_Volumes.m_wstrRootOpened == L"\\\\?\\Volume{1}" );
	CHECK( g_Volumes.m_unAccess == 0x120089 && g_Volumes.m_unShare == 7 && g_Volumes.m_unFlags == 0x02000000 );
	CHECK( g_Volumes.m_nFileId == 0x1122334455667788ll && g_Volumes.m_eType == FileIdType );
	CHECK( g_Volumes.m_cRootsClosed == 1 && g_Volumes.m_cFindsClosed == 1 );

	// image_scan's rebuild passes GENERIC_READ, the parameter keeps that possible.
	g_Volumes = {};
	CHECK( file::OpenByVolumeAndId( &imports, k_unFakeSerialSecond, 1, GENERIC_READ, &hFile, &unLastError ) ==
	       EOpenByIdStatus::Ok );
	CHECK( g_Volumes.m_unAccess == GENERIC_READ );

	g_Volumes = {};
	g_Volumes.m_bFindFails = true;
	CHECK( file::OpenByVolumeAndId( &imports, 1, 1, 0, &hFile, &unLastError ) == EOpenByIdStatus::FindFirstFailed );
	CHECK( unLastError == 0x1234 );

	g_Volumes = {};
	unLastError = 77;
	CHECK( file::OpenByVolumeAndId( &imports, 0xDEAD, 1, 0, &hFile, &unLastError ) ==
	       EOpenByIdStatus::NoVolumeMatched );
	CHECK( unLastError == 0 && g_Volumes.m_cFindsClosed == 1 );

	g_Volumes = {};
	g_Volumes.m_bRootFails = true;
	CHECK( file::OpenByVolumeAndId( &imports, k_unFakeSerialSecond, 1, 0, &hFile, &unLastError ) ==
	       EOpenByIdStatus::NoVolumeMatched );
	CHECK( unLastError == 0x1234 && g_Volumes.m_cRootsClosed == 0 );

	g_Volumes = {};
	g_Volumes.m_bOpenFails = true;
	CHECK( file::OpenByVolumeAndId( &imports, k_unFakeSerialSecond, 1, 0, &hFile, &unLastError ) ==
	       EOpenByIdStatus::OpenFailed );
	CHECK( hFile == INVALID_HANDLE_VALUE && g_Volumes.m_cRootsClosed == 1 && g_Volumes.m_cFindsClosed == 1 );

	static_assert( static_cast<u32>( EOpenByIdStatus::ImportsMissing ) == 78 );
	static_assert( static_cast<u32>( EOpenByIdStatus::FindFirstFailed ) == 91 );
	static_assert( static_cast<u32>( EOpenByIdStatus::OpenFailed ) == 92 );
	static_assert( static_cast<u32>( EOpenByIdStatus::NoVolumeMatched ) == 93 );
}

struct FakeToken_t
{
	DWORD m_unTokenAccess = 0;
	std::string m_strPrivilege;
	DWORD m_unAttributes = 0;
	DWORD m_cubPrivileges = 0;
	LONG m_nLuid = 0;
	u32 m_cAdjusted = 0;
	u32 m_cClosed = 0;
	bool m_bLookupFails = false;
};
FakeToken_t g_Token;

BOOL WINAPI FakeOpenProcessToken( HANDLE, DWORD unAccess, PHANDLE phToken )
{
	g_Token.m_unTokenAccess = unAccess;
	*phToken = reinterpret_cast<HANDLE>( 0x44 );
	return TRUE;
}

BOOL WINAPI FakeLookupPrivilegeValueA( LPCSTR, LPCSTR pszName, PLUID pLuid )
{
	g_Token.m_strPrivilege = pszName;
	pLuid->LowPart = 20;
	pLuid->HighPart = 0;
	return g_Token.m_bLookupFails ? FALSE : TRUE;
}

BOOL WINAPI FakeAdjustTokenPrivileges( HANDLE, BOOL, PTOKEN_PRIVILEGES pPrivileges, DWORD cub, PTOKEN_PRIVILEGES,
                                       PDWORD )
{
	++g_Token.m_cAdjusted;
	g_Token.m_cubPrivileges = cub;
	g_Token.m_unAttributes = pPrivileges->Privileges[0].Attributes;
	g_Token.m_nLuid = static_cast<LONG>( pPrivileges->Privileges[0].Luid.LowPart );
	return TRUE;
}

BOOL WINAPI FakeCloseToken( HANDLE )
{
	++g_Token.m_cClosed;
	return TRUE;
}

BOOL WINAPI FakeGetVersionExA( LPOSVERSIONINFOEXA pVersion )
{
	pVersion->dwPlatformId = 2;
	pVersion->dwMajorVersion = 10;
	pVersion->dwMinorVersion = 3;
	return pVersion->dwOSVersionInfoSize == sizeof( OSVERSIONINFOEXA );
}

void TestProcess()
{
	SystemImports_t imports{};
	g_Token = {};
	process::EnableSeDebugPrivilege( &imports );
	CHECK( g_Token.m_cClosed == 0 );

	imports.GetCurrentProcess = ::GetCurrentProcess;
	imports.OpenProcessToken = FakeOpenProcessToken;
	imports.LookupPrivilegeValueA = FakeLookupPrivilegeValueA;
	imports.AdjustTokenPrivileges = FakeAdjustTokenPrivileges;
	imports.CloseHandle = FakeCloseToken;
	process::EnableSeDebugPrivilege( &imports );
	CHECK( g_Token.m_unTokenAccess == TOKEN_ADJUST_PRIVILEGES && g_Token.m_strPrivilege == "SeDebugPrivilege" );
	CHECK( g_Token.m_cAdjusted == 1 && g_Token.m_unAttributes == SE_PRIVILEGE_ENABLED );
	CHECK( g_Token.m_cubPrivileges == 16 && g_Token.m_nLuid == 20 && g_Token.m_cClosed == 1 );

	g_Token = {};
	g_Token.m_bLookupFails = true;
	process::EnableSeDebugPrivilege( &imports );
	CHECK( g_Token.m_cAdjusted == 0 && g_Token.m_cClosed == 1 );

	static_assert( PROCESS_QUERY_LIMITED_INFORMATION == 0x1000 );
	static_assert( PROCESS_QUERY_INFORMATION == 0x400 );
	static_assert( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ == 0x410 );
	static_assert( process::PackOsVersion( 2, 10, 3 ) == 0x0003'0A02u );

	CHECK( process::QueryPackedOsVersion( &imports ) == 0 );
	imports.GetVersionExA = FakeGetVersionExA;
	CHECK( process::QueryPackedOsVersion( &imports ) == 0x00030A02u );

	// The real snapshot has to contain this process.
	SystemImports_t real{};
	u32 cProcesses = 0;
	CHECK( !process::ForEachSnapshotProcess( &real, []( const PROCESSENTRY32W & ) { return true; } ) );

	real.CreateToolhelp32Snapshot = ::CreateToolhelp32Snapshot;
	real.Process32FirstW = ::Process32FirstW;
	real.Process32NextW = ::Process32NextW;
	real.CloseHandle = ::CloseHandle;
	bool bFoundSelf = false;
	const DWORD unSelf = GetCurrentProcessId();
	CHECK( process::ForEachSnapshotProcess( &real,
	                                        [&]( const PROCESSENTRY32W &entry )
	                                        {
		                                        ++cProcesses;
		                                        bFoundSelf |= entry.th32ProcessID == unSelf;
		                                        return true;
	                                        } ) );
	CHECK( bFoundSelf && cProcesses > 1 );

	u32 cVisited = 0;
	CHECK( process::ForEachSnapshotProcess( &real,
	                                        [&]( const PROCESSENTRY32W & )
	                                        {
		                                        ++cVisited;
		                                        return false;
	                                        } ) );
	CHECK( cVisited == 1 );
}

struct FakeCerts_t
{
	DWORD m_unObjectType = 0;
	DWORD m_unContentFlags = 0;
	u32 m_cubBlob = 0;
	bool m_bQueryFails = false;
	bool m_bNoSigner = false;
	u32 m_cSignerFreed = 0;
	u32 m_cIssuerFreed = 0;
	u32 m_cMsgClosed = 0;
	u32 m_cStoreClosed = 0;
	u32 m_cLocalAllocs = 0;
	u32 m_cLocalFrees = 0;
	const wchar_t *m_pwszSubject = L"Signer";
};
FakeCerts_t g_Certs;

u8 s_rgubSignerBytes[4] = { 1, 2, 3, 4 };
u8 s_rgubIssuerBytes[4] = { 5, 6, 7, 8 };
CERT_CONTEXT s_Signer{ X509_ASN_ENCODING, s_rgubSignerBytes, 4, nullptr, nullptr };
CERT_CONTEXT s_Issuer{ X509_ASN_ENCODING, s_rgubIssuerBytes, 4, nullptr, nullptr };

BOOL WINAPI FakeCryptQueryObject( DWORD unObjectType, const void *pObject, DWORD unContentFlags, DWORD, DWORD, DWORD *,
                                  DWORD *, DWORD *, HCERTSTORE *phStore, HCRYPTMSG *phMsg, const void ** )
{
	g_Certs.m_unObjectType = unObjectType;
	g_Certs.m_unContentFlags = unContentFlags;
	if ( unObjectType == CERT_QUERY_OBJECT_BLOB )
		g_Certs.m_cubBlob = static_cast<const CRYPT_DATA_BLOB *>( pObject )->cbData;
	if ( g_Certs.m_bQueryFails )
		return FALSE;
	*phStore = reinterpret_cast<HCERTSTORE>( 0x51 );
	*phMsg = reinterpret_cast<HCRYPTMSG>( 0x52 );
	return TRUE;
}

BOOL WINAPI FakeCryptMsgGetParam( HCRYPTMSG, DWORD unParam, DWORD, void *pData, DWORD *pcubData )
{
	if ( unParam != CMSG_SIGNER_INFO_PARAM )
		return FALSE;
	if ( !pData )
	{
		*pcubData = sizeof( CMSG_SIGNER_INFO );
		return TRUE;
	}
	std::memset( pData, 0, *pcubData );
	return TRUE;
}

PCCERT_CONTEXT WINAPI FakeCertFindCertificateInStore( HCERTSTORE, DWORD unEncoding, DWORD, DWORD unFindType,
                                                      const void *pFind, PCCERT_CONTEXT )
{
	if ( unEncoding != ( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING ) )
		return nullptr;
	if ( unFindType == CERT_FIND_SUBJECT_CERT )
		return g_Certs.m_bNoSigner ? nullptr : &s_Signer;
	if ( unFindType == CERT_FIND_ISSUER_OF && pFind == &s_Signer )
		return &s_Issuer;
	return nullptr;
}

DWORD WINAPI FakeCertGetNameStringW( PCCERT_CONTEXT pCert, DWORD unType, DWORD, void *, LPWSTR pwszName, DWORD cChars )
{
	if ( unType != CERT_NAME_SIMPLE_DISPLAY_TYPE )
		return 0;
	const wchar_t *pwszSubject = pCert == &s_Issuer ? L"Issuer" : g_Certs.m_pwszSubject;
	const DWORD cNeeded = static_cast<DWORD>( std::wcslen( pwszSubject ) ) + 1;
	if ( !pwszName )
		return cNeeded;
	wcscpy_s( pwszName, cChars, pwszSubject );
	return cNeeded;
}

BOOL WINAPI FakeCryptHashCertificate( HCRYPTPROV_LEGACY, ALG_ID unAlgorithm, DWORD, const BYTE *pubData, DWORD cubData,
                                      BYTE *pubHash, DWORD *pcubHash )
{
	if ( unAlgorithm != CALG_SHA1 || *pcubHash != 20 || cubData != 4 )
		return FALSE;
	std::memset( pubHash, pubData[0], 20 );
	return TRUE;
}

BOOL WINAPI FakeCertFreeCertificateContext( PCCERT_CONTEXT pCert )
{
	if ( pCert == &s_Signer )
		++g_Certs.m_cSignerFreed;
	if ( pCert == &s_Issuer )
		++g_Certs.m_cIssuerFreed;
	return TRUE;
}

BOOL WINAPI FakeCryptMsgClose( HCRYPTMSG )
{
	++g_Certs.m_cMsgClosed;
	return TRUE;
}

BOOL WINAPI FakeCertCloseStore( HCERTSTORE, DWORD )
{
	++g_Certs.m_cStoreClosed;
	return TRUE;
}

HLOCAL WINAPI FakeLocalAlloc( UINT unFlags, SIZE_T cub )
{
	++g_Certs.m_cLocalAllocs;
	return ::LocalAlloc( unFlags, cub );
}

HLOCAL WINAPI FakeLocalFree( HLOCAL hMemory )
{
	++g_Certs.m_cLocalFrees;
	return ::LocalFree( hMemory );
}

void TestVerify()
{
	using namespace verify;

	static_assert( CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED == 1024 );

	SystemImports_t imports{};
	CertContextSet_t set;
	CHECK( !OpenCertificateContext( &imports, &set, L"x" ) );

	imports.CryptQueryObject = FakeCryptQueryObject;
	imports.CryptMsgGetParam = FakeCryptMsgGetParam;
	imports.CertFindCertificateInStore = FakeCertFindCertificateInStore;
	imports.CertGetNameStringW = FakeCertGetNameStringW;
	imports.CryptHashCertificate = FakeCryptHashCertificate;
	imports.CertFreeCertificateContext = FakeCertFreeCertificateContext;
	imports.CryptMsgClose = FakeCryptMsgClose;
	imports.CertCloseStore = FakeCertCloseStore;
	imports.LocalAlloc = FakeLocalAlloc;
	imports.LocalFree = FakeLocalFree;
	imports.GetLastError = FakeGetLastError;
	imports.WideCharToMultiByte = ::WideCharToMultiByte;

	g_Certs = {};
	CHECK( OpenCertificateContext( &imports, &set, L"c:\\x.dll" ) );
	CHECK( g_Certs.m_unObjectType == CERT_QUERY_OBJECT_FILE &&
	       g_Certs.m_unContentFlags == CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED );
	CHECK( set.m_pSigner == &s_Signer && set.m_pIssuer == &s_Issuer );
	CHECK( g_Certs.m_cLocalAllocs == 1 && g_Certs.m_cLocalFrees == 1 );

	CertIdentity_t signer{};
	CertIdentity_t issuer{};
	ExtractCertChain( &imports, &set, &signer, &issuer );
	CHECK( std::strcmp( signer.m_szSubject, "Signer" ) == 0 && signer.m_rgubSha1[0] == 1 &&
	       signer.m_rgubSha1[19] == 1 );
	CHECK( std::strcmp( issuer.m_szSubject, "Issuer" ) == 0 && issuer.m_rgubSha1[0] == 5 );
	CHECK( g_Certs.m_cLocalAllocs == 3 && g_Certs.m_cLocalFrees == 3 );

	// Valve frees the signer and leaks the issuer.
	ReleaseCertContext( &imports, &set );
	CHECK( g_Certs.m_cSignerFreed == 1 && g_Certs.m_cIssuerFreed == 0 );
	CHECK( g_Certs.m_cMsgClosed == 1 && g_Certs.m_cStoreClosed == 1 );
	CHECK( set.m_hStore == nullptr && set.m_pSigner == nullptr && set.m_pIssuer == nullptr );

	g_Certs = {};
	const u8 rgubBlob[8] = {};
	CHECK( OpenCertificateContextFromBlob( &imports, &set, rgubBlob, sizeof( rgubBlob ),
	                                       CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED ) );
	CHECK( g_Certs.m_unObjectType == CERT_QUERY_OBJECT_BLOB &&
	       g_Certs.m_unContentFlags == CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED );
	CHECK( g_Certs.m_cubBlob == 8 );
	ReleaseCertContext( &imports, &set );

	CHECK( !OpenCertificateContextFromBlob( &imports, &set, nullptr, 8, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED ) );
	CHECK( !OpenCertificateContextFromBlob( &imports, &set, rgubBlob, 0, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED ) );

	g_Certs = {};
	g_Certs.m_bQueryFails = true;
	CHECK( !OpenCertificateContext( &imports, &set, L"c:\\x.dll" ) );
	CHECK( set.m_unLastError == 0x1234 );
	ReleaseCertContext( &imports, &set );
	CHECK( g_Certs.m_cMsgClosed == 0 && g_Certs.m_cStoreClosed == 0 );

	g_Certs = {};
	g_Certs.m_bNoSigner = true;
	CHECK( !OpenCertificateContext( &imports, &set, L"c:\\x.dll" ) );
	CHECK( set.m_pSigner == nullptr && set.m_pIssuer == nullptr && set.m_hStore != nullptr );
	CertIdentity_t untouched{};
	ExtractCertChain( &imports, &set, &untouched, &untouched );
	const CertIdentity_t zero{};
	CHECK( BytesEqual( &untouched, &zero, sizeof( zero ) ) );
	ReleaseCertContext( &imports, &set );

	// A subject longer than the field fails the conversion and gets cut at the last byte.
	g_Certs = {};
	g_Certs.m_pwszSubject = L"This subject name is well over forty characters long";
	CHECK( OpenCertificateContext( &imports, &set, L"c:\\x.dll" ) );
	CertIdentity_t longName{};
	ExtractCertChain( &imports, &set, &longName, &issuer );
	CHECK( longName.m_szSubject[sizeof( longName.m_szSubject ) - 1] == 0 );
	CHECK( std::strncmp( longName.m_szSubject, "This subject name is well over forty ch", 39 ) == 0 );
	ReleaseCertContext( &imports, &set );
}

struct Area_t
{
	const char *m_pszName;
	void ( *m_pfnRun )();
};

} // namespace

int main()
{
	const Area_t rgAreas[] = {
	    { "ice", TestIce },
	    { "hashes", TestHashes },
	    { "park_miller", TestParkMiller },
	    { "bignum", TestBignum },
	    { "rsa", TestRsa },
	    { "parse_tlv", TestParseTlv },
	    { "strings", TestStrings },
	    { "encoding", TestEncoding },
	    { "layouts", TestLayouts },
	    { "pe", TestPe },
	    { "lz4", TestLz4 },
	    { "file_read", TestFileSizeAndRead },
	    { "file_by_id", TestOpenById },
	    { "process", TestProcess },
	    { "verify", TestVerify },
	};

	for ( const Area_t &area : rgAreas )
	{
		const int cChecksBefore = g_cChecks;
		const int cFailuresBefore = g_cFailures;
		area.m_pfnRun();
		std::printf( "%-12s checks=%d failures=%d\n", area.m_pszName, g_cChecks - cChecksBefore,
		             g_cFailures - cFailuresBefore );
	}

	std::printf( "areas=%u checks=%d failures=%d\n", static_cast<unsigned>( sizeof( rgAreas ) / sizeof( rgAreas[0] ) ),
	             g_cChecks, g_cFailures );
	return g_cFailures ? 1 : 0;
}
