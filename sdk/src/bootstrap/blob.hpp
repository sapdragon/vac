#pragma once

#include "bootstrap/imports.hpp"
#include "core/types.hpp"
#include "crypto/ice/ice.hpp"

// @note / sapdragon: valve encrypts this with the first 8 input bytes, so the key differs per build. same text

namespace vac::bootstrap
{

struct ImportEntry_t
{
	u32 m_ibLibrary;
	u32 m_ibFunction;
};

struct BootstrapBlob_t
{
	u8 m_rgub[0xFC0];
};

namespace detail
{

struct ImportName_t
{
	const char *m_szLibrary;
	const char *m_szFunction;
};

inline constexpr ImportName_t k_rgImportNames[] = {
#define VAC_IMPORT( szLibrary, ReturnType, Name, Args ) { szLibrary, #Name },
#include "bootstrap/imports.inl"
#undef VAC_IMPORT
};
static_assert( ARRAYSIZE( k_rgImportNames ) == 172 );

} // namespace detail

struct BlobImage_t
{
	BootstrapBlob_t m_Blob;
	ImportEntry_t m_rgEntries[ARRAYSIZE( detail::k_rgImportNames ) + 1];
};

namespace detail
{

consteval bool StringsEqual( const char *pszA, const char *pszB )
{
	while ( *pszA && *pszA == *pszB )
	{
		++pszA;
		++pszB;
	}
	return *pszA == *pszB;
}

consteval u32 AppendString( BootstrapBlob_t &blob, u32 &ibWrite, const char *pszText )
{
	const u32 ibString = ibWrite;
	while ( *pszText )
		blob.m_rgub[ibWrite++] = static_cast<u8>( *pszText++ );
	blob.m_rgub[ibWrite++] = 0;
	return ibString;
}

} // namespace detail

consteval BlobImage_t BuildBlobImage()
{
	constexpr u8 k_rgubHeader[] = { 0xC9, 0xB8, 0x7C, 0xAD, 0xC0, 0x0F, 0x00, 0x00,
	                                0x39, 0xCE, 0xC0, 0x8C, 0x00, 0x00, 0x00, 0x00 };

	BlobImage_t image{};
	for ( u32 ib = 0; ib < ARRAYSIZE( k_rgubHeader ); ++ib )
		image.m_Blob.m_rgub[ib] = k_rgubHeader[ib];

	u32 ibWrite = ARRAYSIZE( k_rgubHeader );
	for ( u32 iImport = 0; iImport < ARRAYSIZE( detail::k_rgImportNames ); ++iImport )
	{
		const detail::ImportName_t &name = detail::k_rgImportNames[iImport];

		// @note / sapdragon: offset 0 stays free, a zero library offset ends the list
		u32 ibLibrary = 0;
		for ( u32 iPrevious = 0; iPrevious < iImport && !ibLibrary; ++iPrevious )
		{
			if ( detail::StringsEqual( detail::k_rgImportNames[iPrevious].m_szLibrary, name.m_szLibrary ) )
				ibLibrary = image.m_rgEntries[iPrevious].m_ibLibrary;
		}
		if ( !ibLibrary )
			ibLibrary = detail::AppendString( image.m_Blob, ibWrite, name.m_szLibrary );

		image.m_rgEntries[iImport].m_ibLibrary = ibLibrary;
		image.m_rgEntries[iImport].m_ibFunction = detail::AppendString( image.m_Blob, ibWrite, name.m_szFunction );
	}
	return image;
}

inline constexpr BlobImage_t k_BlobImage = BuildBlobImage();

extern const BootstrapBlob_t g_EncryptedBlob;

} // namespace vac::bootstrap
