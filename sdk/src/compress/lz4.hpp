// @binary: 78a6ef0f
#pragma once

#include "core/types.hpp"
#include "crt/intrinsics.hpp"
#include "util/strings.hpp"

namespace vac::compress::lz4
{

inline constexpr u32 k_cHashLogBits = 13u;
inline constexpr u32 k_cubMinMatch = 4u;
inline constexpr u32 k_cubMaxInput = 0x7E000000u;

constexpr u32 CompressBound( u32 cubInput ) noexcept
{
	return cubInput <= k_cubMaxInput ? cubInput + cubInput / 255u + 16u : 0;
}

constexpr u32 Hash( u32 unSequence ) noexcept
{
	return ( unSequence * 2654435761u ) >> ( ( k_cubMinMatch * 8u ) - k_cHashLogBits );
}

constexpr u32 CommonBytes( u32 unDifference ) noexcept
{
	if ( !unDifference )
		return 4;
	u32 cBytes = 0;
	while ( ( unDifference & 0xFFu ) == 0 )
	{
		++cBytes;
		unDifference >>= 8;
	}
	return cBytes;
}

// @note / sapdragon: 16-bit positions only, like valve's small-input path. their 64 KB path is not rebuilt, the
// report never gets that big
// @orig: 81 EC ? ? ? ? 53 55 56 57 8B FA
inline int Compress( const u8 *pubInput, u8 *pubOutput, u32 cubInput, u32 cubOutput ) noexcept
{
	if ( !cubInput )
		return 0;
	if ( CompressBound( cubInput ) > cubOutput )
		return 0;

	u16 rgunTable[1u << k_cHashLogBits];
	memset( rgunTable, 0, sizeof( rgunTable ) );

	const u8 *const pubBase = pubInput;
	const u8 *const pubInputEnd = pubInput + cubInput;
	const u8 *const pubMatchFindLimit = pubInputEnd - 11;
	const u8 *pubAnchor = pubInput;
	const u8 *pubCursor = pubInput + 1;
	u32 unForwardHash = 0;
	u8 *pubWrite = pubOutput;

	if ( cubInput < 13u )
		goto last_literals;

	rgunTable[Hash( util::Read32( pubInput ) )] = 0;
	unForwardHash = Hash( util::Read32( pubCursor ) );

	for ( ;; )
	{
		const u8 *pubMatch;
		const u8 *pubForward = pubCursor;
		u32 cubStep = 1;
		u32 cSearches = 64;

		do
		{
			pubCursor = pubForward;
			pubForward += cubStep;
			cubStep = cSearches++ >> 6;
			if ( pubForward > pubMatchFindLimit )
				goto last_literals;

			const u32 unHash = unForwardHash;
			const u16 unPosition = rgunTable[unHash];
			pubMatch = pubBase + unPosition;
			unForwardHash = Hash( util::Read32( pubForward ) );
			rgunTable[unHash] = static_cast<u16>( pubCursor - pubBase );
		} while ( ( pubCursor - pubMatch > 0xFFFF ) || util::Read32( pubMatch ) != util::Read32( pubCursor ) );

		while ( pubCursor > pubAnchor && pubMatch > pubBase && pubCursor[-1] == pubMatch[-1] )
		{
			--pubCursor;
			--pubMatch;
		}

		{
			const u32 cubLiterals = static_cast<u32>( pubCursor - pubAnchor );
			u8 *pubToken = pubWrite++;
			if ( cubLiterals >= 15u )
			{
				*pubToken = 15u << 4;
				const u32 cubRemaining = cubLiterals - 15u;
				if ( cubRemaining < 255u )
				{
					*pubWrite++ = static_cast<u8>( cubRemaining );
				}
				else
				{
					const u32 cBlocks = cubRemaining / 255u;
					memset( pubWrite, 255, cBlocks );
					pubWrite += cBlocks;
					*pubWrite++ = static_cast<u8>( cubRemaining % 255u );
				}
			}
			else
			{
				*pubToken = static_cast<u8>( cubLiterals << 4 );
			}

			memcpy( pubWrite, pubAnchor, cubLiterals );
			pubWrite += cubLiterals;

			for ( ;; )
			{
				util::Write16( pubWrite, static_cast<u16>( pubCursor - pubMatch ) );
				pubWrite += 2;

				pubCursor += k_cubMinMatch;
				pubMatch += k_cubMinMatch;

				const u8 *pubMatchStart = pubCursor;
				while ( pubCursor < pubInputEnd - 8 )
				{
					const u32 unDifference = util::Read32( pubMatch ) ^ util::Read32( pubCursor );
					if ( unDifference )
					{
						pubCursor += CommonBytes( unDifference );
						goto match_done;
					}
					pubCursor += 4;
					pubMatch += 4;
				}
				if ( pubCursor < pubInputEnd - 6 &&
				     *reinterpret_cast<const u16 *>( pubMatch ) == *reinterpret_cast<const u16 *>( pubCursor ) )
				{
					pubCursor += 2;
					pubMatch += 2;
				}
				if ( pubCursor < pubInputEnd - 5 && *pubMatch == *pubCursor )
					++pubCursor;

			match_done:
			{
				u32 cubMatch = static_cast<u32>( pubCursor - pubMatchStart );
				if ( cubMatch >= 15u )
				{
					*pubToken += 15u;
					cubMatch -= 15u;
					u32 unFill = 0xFFFFFFFFu;
					memcpy( pubWrite, &unFill, 4 );
					if ( cubMatch >= 1020u )
					{
						u32 cBlocks = cubMatch / 1020u;
						do
						{
							pubWrite += 4;
							memcpy( pubWrite, &unFill, 4 );
							--cBlocks;
						} while ( cBlocks );
						cubMatch %= 1020u;
					}
					pubWrite += cubMatch / 255u;
					*pubWrite++ = static_cast<u8>( cubMatch % 255u );
				}
				else
				{
					*pubToken = static_cast<u8>( *pubToken + cubMatch );
				}
			}

				pubAnchor = pubCursor;
				if ( pubCursor >= pubMatchFindLimit )
					goto last_literals;

				rgunTable[Hash( util::Read32( pubCursor - 2 ) )] = static_cast<u16>( ( pubCursor - 2 ) - pubBase );
				const u32 unHash = Hash( util::Read32( pubCursor ) );
				pubMatch = pubBase + rgunTable[unHash];
				rgunTable[unHash] = static_cast<u16>( pubCursor - pubBase );
				if ( pubCursor - pubMatch > 0xFFFF || util::Read32( pubMatch ) != util::Read32( pubCursor ) )
				{
					unForwardHash = Hash( util::Read32( ++pubCursor ) );
					break;
				}
				pubToken = pubWrite++;
				*pubToken = 0;
			}
		}
	}

last_literals:
{
	const u32 cubLiterals = static_cast<u32>( pubInputEnd - pubAnchor );
	if ( !cubLiterals )
		return static_cast<int>( pubWrite - pubOutput );

	u8 *pubToken = pubWrite++;
	if ( cubLiterals >= 15u )
	{
		*pubToken = 15u << 4;
		const u32 cubRemaining = cubLiterals - 15u;
		if ( cubRemaining < 255u )
		{
			*pubWrite++ = static_cast<u8>( cubRemaining );
		}
		else
		{
			const u32 cBlocks = cubRemaining / 255u;
			memset( pubWrite, 255, cBlocks );
			pubWrite += cBlocks;
			*pubWrite++ = static_cast<u8>( cubRemaining % 255u );
		}
	}
	else
	{
		*pubToken = static_cast<u8>( cubLiterals << 4 );
	}
	memcpy( pubWrite, pubAnchor, cubLiterals );
	pubWrite += cubLiterals;
}

	return static_cast<int>( pubWrite - pubOutput );
}

} // namespace vac::compress::lz4
