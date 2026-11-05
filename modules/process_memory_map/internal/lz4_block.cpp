// @binary: 8d88e017
#include "compress/lz4.hpp"
#include "crt/intrinsics.hpp"
#include "internal/report_builder.hpp"

namespace vac::workers::process_memory_map
{

// @orig: 80 B9 ? ? ? ? ? 8B 41 ? 8B 51
i32 GetPlainSize( ReportBuilder_t &builder ) noexcept
{
	const i32 cubTables = builder.m_bWideRecords
	                          ? builder.m_cHashes * static_cast<i32>( sizeof( ImageHashRecord64_t ) ) +
	                                builder.m_cRecords * static_cast<i32>( sizeof( ModuleRecord64_t ) )
	                          : builder.m_cHashes * static_cast<i32>( sizeof( ImageHashRecord32_t ) ) +
	                                builder.m_cRecords * static_cast<i32>( sizeof( ModuleRecord32_t ) );
	builder.m_cubPlain = cubTables + builder.m_cubStrings;
	return builder.m_cubPlain;
}

// @orig: 80 B9 ? ? ? ? ? 8B 41 ? 75
i32 GetRecordBytes( const ReportBuilder_t &builder ) noexcept
{
	return builder.m_bWideRecords ? builder.m_cRecords * static_cast<i32>( sizeof( ModuleRecord64_t ) )
	                              : builder.m_cRecords * static_cast<i32>( sizeof( ModuleRecord32_t ) );
}

// @note / sapdragon: the size can be over the limit, only a block that fits gets written
// @orig: 55 8B EC B8 ? ? ? ? E8 ? ? ? ? 53
i32 CompressRecords( ReportBuilder_t &builder, u8 *pubOutput ) noexcept
{
	u8 rgubPlain[11200];
	const i32 cubHashes =
	    builder.m_cHashes *
	    static_cast<i32>( builder.m_bWideRecords ? sizeof( ImageHashRecord64_t ) : sizeof( ImageHashRecord32_t ) );
	const i32 cubRecords = GetRecordBytes( builder );
	memcpy( rgubPlain, builder.m_pubHashes, cubHashes );
	memcpy( rgubPlain + cubHashes, builder.m_pubRecords, cubRecords );
	memcpy( rgubPlain + cubHashes + cubRecords, builder.m_rgchStrings, builder.m_cubStrings );

	const i32 cubPlain = cubHashes + cubRecords + builder.m_cubStrings;
	builder.m_cubPlain = cubPlain;

	// @note / sapdragon: lz4::Compress wants the worst case output, valve only has 11200 and aborts when it runs out.
	// a bigger buffer gives the same bytes, a block that doesn't fit counts as a failure. the abort check itself is a
	// little stricter near the limit, so a block of almost 11200 bytes can differ. it needs a near incompressible report
	u8 rgubCompressed[compress::lz4::CompressBound( sizeof( rgubPlain ) )];
	i32 cubCompressed;
	if ( cubPlain )
	{
		cubCompressed = compress::lz4::Compress( rgubPlain, rgubCompressed, cubPlain, sizeof( rgubCompressed ) );
		if ( cubCompressed > static_cast<i32>( sizeof( rgubPlain ) ) )
			cubCompressed = 0;
	}
	else
	{
		// @note / sapdragon: valve's lz4 emits one zero token for empty input, lz4::Compress returns 0 instead
		rgubCompressed[0] = 0;
		cubCompressed = 1;
	}

	if ( cubCompressed && cubCompressed <= static_cast<i32>( sizeof( Report_t::m_rgubCompressed ) ) )
		memcpy( pubOutput, rgubCompressed, cubCompressed );
	return cubCompressed;
}

} // namespace vac::workers::process_memory_map
