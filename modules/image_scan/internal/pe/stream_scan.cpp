// @binary: 33211402
#include "../scanner.hpp"
#include "stream_scan_tables.hpp"
#include "crt/intrinsics.hpp"
#include "crypto/hash/md5.hpp"
#include "util/hashing.hpp"
#include "util/strings.hpp"

namespace vac::workers::image_scan
{

namespace
{

constexpr u32 k_cubStreamChunk = 0x40000;
constexpr u32 k_iFirstLongHash = 4;
constexpr u32 k_cRotatingHashes = 3;
constexpr u32 k_cubPage = 0x1000;

enum class EByteClass : u32
{
	None = 0,
	Zero = 1,
	SmallConstant = 2,
	NearOffset = 3,
	FunctionStart = 4,
	Lookup = 5,
	Text = 8,
	Separator = 9,
};

enum class EFunctionProlog : u32
{
	PushEbpMovEbpEsp = 0xEC8B55,
	PushEdiMovEdiEcx = 0xF98B57,
};

// @note / sapdragon: the original keeps these on the stack and never reads them back
struct StreamStats_t
{
	u32 m_cZeros;
	u32 m_cPadding;
	u32 m_cMatchTries;
	u32 m_cProlog;
	u32 m_cSmallConstant;
	u32 m_cNearOffset;
	u32 m_rgunUnused[2];
	u32 m_cubCode;
	u32 m_cubData;
};

#pragma pack( push, 1 )
struct StreamMatch_t
{
	u64 m_ulBase;
	u32 m_ibMatch;
	u32 m_unHash;
	u32 m_unUnused;
	u16 m_unTag;
	u8 m_cchMatch;
	u8 m_cSeen;
};
struct StreamPatternScanner_t
{
	u32 m_unReserved0;
	u64 m_ulBase;
	u8 m_rgubUnused0[12];
	u16 m_unTag;
	u8 m_rgubUnused1[2];
	StreamMatch_t *m_pMatches;
	u32 m_cMatches;
	u32 m_cMaxMatches;
	PatternReport_t *m_pPatterns;
	StreamStats_t *m_pStats;
	u32 m_cCustomHashes;
	const u32 *m_punCustomHashes;
	char *m_pszText;
	u32 m_unReserved1;
	i32 m_cubTextLeft;
};
#pragma pack( pop )
VAC_LAYOUT_SIZE( StreamMatch_t, 24 );
VAC_LAYOUT( StreamPatternScanner_t, m_pMatches, 0x1C );
VAC_LAYOUT( StreamPatternScanner_t, m_pPatterns, 0x28 );
VAC_LAYOUT( StreamPatternScanner_t, m_pszText, 0x38 );
VAC_LAYOUT( StreamPatternScanner_t, m_cubTextLeft, 0x40 );

// @orig: 8B 51 ? 56 85 D2
int LookupStreamPatternHash( const StreamPatternScanner_t *pScanner, u32 unHash ) noexcept
{
	if ( pScanner->m_cCustomHashes && pScanner->m_punCustomHashes )
	{
		for ( u32 iHash = 0; iHash < pScanner->m_cCustomHashes; ++iHash )
		{
			if ( pScanner->m_punCustomHashes[iHash] == unHash )
				return static_cast<int>( iHash );
		}
		return -1;
	}

	for ( u32 iHash = unHash % ARRAYSIZE( k_rgunPatternHashes );;
	      iHash = ( iHash + 1 ) % ARRAYSIZE( k_rgunPatternHashes ) )
	{
		const u32 unCandidate = k_rgunPatternHashes[iHash];
		if ( !unCandidate )
			return -1;
		if ( unCandidate == unHash )
			return k_rgunPatternIds[iHash];
	}
}

// @orig: 83 EC ? 53 55 56 57 6A
int CopyPrintableRuns( const u8 *pubSource, u32 cubSource, char *pszDst, u32 *pcubTailDropped ) noexcept
{
	u8 rgubCompact[64];
	const i32 cubLimit = cubSource <= sizeof( rgubCompact ) ? static_cast<i32>( cubSource ) : sizeof( rgubCompact );

	i32 cubCompact = 0;
	for ( i32 ib = 0; ib < cubLimit; ++ib )
	{
		if ( pubSource[ib] )
			rgubCompact[cubCompact++] = pubSource[ib];
	}

	int cubCopied = 0;
	i32 iRunStart = -1;
	for ( i32 ib = 0; ib < cubCompact; )
	{
		const u8 unClass = k_rgunSignedByteClass[128 + static_cast<i8>( rgubCompact[ib] )];
		if ( unClass >= static_cast<u8>( EByteClass::Text ) && iRunStart == -1 )
			iRunStart = ib;
		++ib;
		*pcubTailDropped = 0;
		if ( unClass >= static_cast<u8>( EByteClass::Text ) && ib != cubCompact )
			continue;

		if ( iRunStart >= 0 )
		{
			const i32 cubRun = ib - iRunStart;
			if ( cubRun < 4 )
			{
				*pcubTailDropped = static_cast<u32>( cubRun );
			}
			else
			{
				memcpy( pszDst, &rgubCompact[iRunStart], static_cast<u32>( cubRun ) );
				pszDst += cubRun;
				cubCopied += cubRun;
			}
			iRunStart = -1;
		}
	}
	return cubCopied;
}

// @orig: 53 8B D9 55 8B 6B
void AppendNearbyAsciiRuns( StreamPatternScanner_t *pScanner, const u8 *pubChunk, u32 cubChunk, u32 ibMatchEnd,
                            u32 cubMatch, u32 *pibCursor ) noexcept
{
	char *pszText = pScanner->m_pszText;
	if ( !pszText )
		return;

	const i32 cubTextLeft = pScanner->m_cubTextLeft;
	i32 cubWanted = cubTextLeft - 1;
	if ( cubTextLeft >= static_cast<i32>( cubMatch + 33 ) )
		cubWanted = static_cast<i32>( cubMatch + 32 );

	u32 ibStart = 0;
	if ( static_cast<i32>( ibMatchEnd - cubMatch - 16 ) >= 0 )
		ibStart = ibMatchEnd - cubMatch - 16;

	u32 ibFrom = *pibCursor;
	const i32 cubOverlap = static_cast<i32>( *pibCursor - ibStart );
	i32 cubCopy = cubWanted - cubOverlap;
	if ( cubOverlap <= 0 )
	{
		ibFrom = ibStart;
		cubCopy = cubWanted;
	}
	if ( cubCopy <= 0 )
		return;

	u32 cubTailDropped = 0;
	*pibCursor = static_cast<u32>( cubCopy ) + ibFrom;
	u32 cubAvailable = cubChunk - ibFrom;
	if ( static_cast<i32>( static_cast<u32>( cubCopy ) + ibFrom - cubChunk ) <= 0 )
		cubAvailable = static_cast<u32>( cubCopy );

	const int cubCopied = CopyPrintableRuns( &pubChunk[ibFrom], cubAvailable, pszText, &cubTailDropped );
	*pibCursor -= cubTailDropped;
	pszText[cubCopied] = 0;
	pScanner->m_cubTextLeft -= cubCopied;
	pScanner->m_pszText = pszText + cubCopied;
	if ( pScanner->m_cubTextLeft < 20 )
		pScanner->m_pszText = nullptr;
}

// @note / sapdragon: the match list is always null in this build, so this does nothing
// @orig: 56 8B F1 8B 4E
void RecordStreamPatternMatch( StreamPatternScanner_t *pScanner, u32 unHash, u32 ibMatch, u8 cchMatch ) noexcept
{
	if ( !pScanner->m_pMatches || !pScanner->m_cMaxMatches )
		return;

	for ( u32 iMatch = 0; iMatch < pScanner->m_cMatches; ++iMatch )
	{
		StreamMatch_t &match = pScanner->m_pMatches[iMatch];
		if ( match.m_unHash != unHash )
			continue;
		if ( match.m_ibMatch == ibMatch && match.m_ulBase == pScanner->m_ulBase )
			return;
		if ( match.m_cSeen != 0xFF )
			++match.m_cSeen;
		if ( match.m_cSeen >= 0x10 )
			return;
		break;
	}

	if ( pScanner->m_cMatches < pScanner->m_cMaxMatches )
	{
		StreamMatch_t &match = pScanner->m_pMatches[pScanner->m_cMatches];
		match.m_ulBase = pScanner->m_ulBase;
		match.m_unUnused = 0;
		match.m_unTag = pScanner->m_unTag;
		match.m_unHash = unHash;
		match.m_ibMatch = ibMatch;
		match.m_cSeen = 1;
		match.m_cchMatch = cchMatch;
		++pScanner->m_cMatches;
	}
}

void SetPatternBit( const StreamPatternScanner_t *pScanner, int nPattern ) noexcept
{
	if ( nPattern < 256 && pScanner->m_pPatterns )
		pScanner->m_pPatterns->m_rgunPatternBits[nPattern >> 5] |= 1u << ( nPattern % 32 );
}

// @note / sapdragon: eight rolling hashes over byte classes. the last four see every second byte too, for utf-16
// @orig: 81 EC ? ? ? ? 53 55 56 57 8B E9
void ScanStreamPatterns( StreamPatternScanner_t *pScanner, const u8 *pubChunk, u32 cubChunk ) noexcept
{
	u32 rgcchMatch[8] = {};
	u32 rgunHash[ARRAYSIZE( rgcchMatch )];
	for ( u32 &unHash : rgunHash )
		unHash = util::hashing::k_unHashSeed;

	u32 unRawHash = util::hashing::k_unHashSeed;
	EByteClass ePreviousClass = EByteClass::None;
	u32 iRotate = 0;
	u32 ibCursor = 0;
	u32 iPage = 0;
	u32 cZerosInPage = 0;
	i32 cCodeHits = 0;

	for ( u32 ib = 0; ib < cubChunk; ++ib )
	{
		unRawHash = pubChunk[ib] + 33 * unRawHash;
		const EByteClass eClass = static_cast<EByteClass>( k_rgunByteClass[pubChunk[ib]] );

		if ( eClass > EByteClass::Separator )
		{
			for ( u32 iHash = 0; iHash < ARRAYSIZE( rgunHash ); ++iHash )
			{
				++rgcchMatch[iHash];
				rgunHash[iHash] = static_cast<u32>( eClass ) + 33 * rgunHash[iHash];
			}
		}
		else
		{
			u32 cchLast = 0;
			for ( u32 iHash = 0; iHash < ARRAYSIZE( rgunHash ); ++iHash )
			{
				u32 cchMatch = rgcchMatch[iHash];
				if ( cchMatch >= 3 && cchMatch != cchLast )
				{
					if ( pScanner->m_pStats )
						++pScanner->m_pStats->m_cMatchTries;

					const u32 cchRun = cchMatch;
					const int nPattern = LookupStreamPatternHash( pScanner, rgunHash[iHash] );
					if ( nPattern >= 0 )
					{
						if ( iHash >= k_iFirstLongHash )
							cchMatch = 2 * cchMatch - 1;
						RecordStreamPatternMatch( pScanner, rgunHash[iHash], ib - cchMatch,
						                          static_cast<u8>( cchMatch ) );
						SetPatternBit( pScanner, nPattern );
						AppendNearbyAsciiRuns( pScanner, pubChunk, cubChunk, ib,
						                       iHash < k_iFirstLongHash ? cchMatch : 2 * cchMatch, &ibCursor );
					}
					cchLast = cchRun;
				}
			}

			if ( eClass == EByteClass::Separator )
			{
				for ( u32 iHash = 0; iHash < ARRAYSIZE( rgunHash ); ++iHash )
				{
					++rgcchMatch[iHash];
					rgunHash[iHash] = static_cast<u32>( EByteClass::Separator ) + 33 * rgunHash[iHash];
				}
				rgcchMatch[iRotate] = 0;
				rgcchMatch[k_iFirstLongHash + iRotate] = 0;
				rgunHash[iRotate] = util::hashing::k_unHashSeed;
				rgunHash[k_iFirstLongHash + iRotate] = util::hashing::k_unHashSeed;
				iRotate = ( iRotate + 1 ) % k_cRotatingHashes;
			}
			else
			{
				for ( u32 iHash = 0; iHash < k_cRotatingHashes; ++iHash )
				{
					rgcchMatch[iHash] = 0;
					rgunHash[iHash] = util::hashing::k_unHashSeed;
				}

				bool bResetLong = true;
				if ( eClass == EByteClass::Zero )
				{
					rgcchMatch[3] = 0;
					rgunHash[3] = util::hashing::k_unHashSeed;
					bResetLong = ePreviousClass == EByteClass::Zero;
				}
				else
				{
					++rgcchMatch[3];
					rgunHash[3] = static_cast<u32>( eClass ) + 33 * rgunHash[3];
				}

				if ( bResetLong )
				{
					for ( u32 iHash = k_iFirstLongHash; iHash < k_iFirstLongHash + k_cRotatingHashes; ++iHash )
					{
						rgcchMatch[iHash] = 0;
						rgunHash[iHash] = util::hashing::k_unHashSeed;
					}
					if ( eClass == EByteClass::Zero && ePreviousClass == EByteClass::Zero )
					{
						rgcchMatch[7] = 0;
						rgunHash[7] = util::hashing::k_unHashSeed;
					}
					else
					{
						++rgcchMatch[7];
						rgunHash[7] = static_cast<u32>( eClass ) + 33 * rgunHash[7];
					}
				}

				StreamStats_t *pStats = pScanner->m_pStats;
				if ( pStats )
				{
					bool bLookUp = false;
					if ( eClass == EByteClass::Zero )
					{
						++pStats->m_cZeros;
						++cZerosInPage;
					}
					else if ( eClass == EByteClass::SmallConstant )
					{
						if ( cubChunk - ib >= 2 && !pubChunk[ib + 2] && pubChunk[ib + 1] <= 0x20 &&
						     !( pubChunk[ib + 1] & 3 ) )
						{
							++pStats->m_cSmallConstant;
							++cCodeHits;
							bLookUp = true;
						}
					}
					else if ( eClass == EByteClass::NearOffset )
					{
						if ( cubChunk - ib >= 4 )
						{
							const i32 nOffset = *reinterpret_cast<const i32 *>( &pubChunk[ib + 1] );
							if ( nOffset < 0x80000 && static_cast<u32>( nOffset ) > 0xFFF80000u )
							{
								++pStats->m_cNearOffset;
								++cCodeHits;
							}
						}
					}
					else if ( eClass == EByteClass::FunctionStart )
					{
						// @note / sapdragon: reads a dword from the aligned offset, up to 3 bytes past a short chunk.
						// these reset the raw hash, so the prologs are part of what the patterns match
						const u32 unWord = *reinterpret_cast<const u32 *>( &pubChunk[ib & ~3u] );
						if ( unWord == 0xCCCCCCCC && ( ib & 3 ) == 3 )
						{
							++pStats->m_cPadding;
							unRawHash = util::hashing::k_unHashSeed;
						}
						const EFunctionProlog eProlog = static_cast<EFunctionProlog>( unWord & 0xFFFFFF );
						if ( eProlog == EFunctionProlog::PushEbpMovEbpEsp ||
						     eProlog == EFunctionProlog::PushEdiMovEdiEcx )
						{
							unRawHash = util::hashing::k_unHashSeed;
							++pStats->m_cProlog;
							++cCodeHits;
						}
					}
					else if ( eClass == EByteClass::Lookup )
					{
						bLookUp = true;
					}

					if ( bLookUp )
					{
						const int nPattern = LookupStreamPatternHash( pScanner, unRawHash );
						if ( nPattern >= 0 )
						{
							// @note / sapdragon: the original indexes its match lengths with the pattern id here, a wild
							// stack read that goes nowhere since the match list is null. dropped along with the read
							RecordStreamPatternMatch( pScanner, unRawHash, ib, 0 );
							SetPatternBit( pScanner, nPattern );
						}
					}
				}
			}
		}

		ePreviousClass = eClass;
		const u32 iNextPage = ( ib + 1 ) >> 12;
		if ( iNextPage != iPage )
		{
			StreamStats_t *pStats = pScanner->m_pStats;
			if ( pStats )
			{
				if ( cubChunk == k_cubPage )
					pStats->m_cubData += k_cubPage - cZerosInPage;
				else if ( cZerosInPage != k_cubPage )
					pStats->m_cubData += k_cubPage;
				if ( cCodeHits > 50 )
					pStats->m_cubCode += k_cubPage;
			}
			iPage = iNextPage;
			cCodeHits = 0;
			cZerosInPage = 0;
		}
	}
}

} // namespace

// @orig: 81 EC ? ? ? ? 53 55 56 89 4C 24
bool HashStreamAndScanPatterns( ScannerContext_t *pCtx, u32 cubStream, ModuleReport_t *pModule,
                                PatternReport_t *pPatterns ) noexcept
{
	crypto::hash::Md5_t md5;

	StreamStats_t stats = {};
	StreamPatternScanner_t scanner{};
	scanner.m_pPatterns = pPatterns;
	scanner.m_pStats = &stats;
	scanner.m_pszText = &pPatterns->m_szText[pPatterns->m_cubText];
	scanner.m_cubTextLeft = static_cast<i32>( sizeof( pPatterns->m_szText ) - pPatterns->m_cubText );

	u8 *pubChunk = static_cast<u8 *>( AllocBytes( k_cubStreamChunk ) );
	if ( !pubChunk )
	{
		pModule->m_cubStream |= k_unFailedFlag;
		return false;
	}

	u32 ibOffset = 0;
	u32 cubTotal = 0;
	while ( cubStream )
	{
		const u32 cubRead =
		    ReaderReadAt( pCtx, ibOffset, pubChunk, cubStream < k_cubStreamChunk ? cubStream : k_cubStreamChunk );
		if ( !cubRead )
			break;

		md5.Update( pubChunk, cubRead );
		ibOffset += cubRead;
		ScanStreamPatterns( &scanner, pubChunk, cubRead );
		cubTotal += cubRead;
		cubStream -= cubRead;
	}
	FreeBytes( pubChunk );

	pPatterns->m_cubText = sizeof( pPatterns->m_szText ) - static_cast<u32>( scanner.m_cubTextLeft );
	pModule->m_cubStream ^= ( cubTotal ^ pModule->m_cubStream ) & k_unByteCountMask;
	if ( cubTotal )
	{
		md5.Final( pModule->m_rgubStreamMd5 );
		if ( !pModule->m_cReportedHashes )
			pModule->m_cReportedHashes = 1;
	}
	return true;
}

} // namespace vac::workers::image_scan
