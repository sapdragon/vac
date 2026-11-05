// @binary: 8d88e017
#include "crt/intrinsics.hpp"
#include "internal/report_builder.hpp"
#include "util/encoding.hpp"
#include "util/hashing.hpp"
#include "util/strings.hpp"
#include "util/wstr.hpp"

namespace vac::workers::process_memory_map
{

// @orig: 33 C0 88 01 88 81
void ResetPathEntry( PathEntry_t &entry ) noexcept
{
	entry.m_szDirectory[0] = 0;
	entry.m_szBaseName[0] = 0;
	entry.m_cchDirectory = 0;
	entry.m_cchBaseName = 0;
	entry.m_bInSystemDirectory = false;
	entry.m_bInWindowsDirectory = false;
	entry.m_unDirectoryHash = 0;
	entry.m_unBaseNameHash = 0;
	entry.m_bHasPath = false;
}

// @orig: 8B 54 24 ? 81 EC
void BuildPathEntry( PathEntry_t &entry, const wchar_t *pwszPath, const SystemDirectories_t &directories,
                     const SystemImports_t *pImports ) noexcept
{
	wchar_t wszDirectory[MAX_PATH];
	CopyWideFilled( wszDirectory, pwszPath, MAX_PATH );

	wchar_t *pwszBaseName = const_cast<wchar_t *>( util::wstr::BaseName( wszDirectory ) );
	entry.m_bHasPath = true;
	if ( pwszBaseName > wszDirectory )
		pwszBaseName[-1] = 0;

	util::encoding::WideToUtf8Bounded( pImports, wszDirectory, entry.m_szDirectory, MAX_PATH );
	util::encoding::WideToUtf8Bounded( pImports, pwszBaseName, entry.m_szBaseName, MAX_PATH );
	entry.m_cchDirectory = static_cast<i32>( util::StrLenA( entry.m_szDirectory ) );
	entry.m_cchBaseName = static_cast<i32>( util::StrLenA( entry.m_szBaseName ) );

	if ( lstrlenW( wszDirectory ) >= directories.m_cchSystem )
	{
		wszDirectory[directories.m_cchSystem] = 0;
		if ( lstrcmpiW( directories.m_wszSystem, wszDirectory ) == 0 )
			entry.m_bInSystemDirectory = true;
	}
	if ( lstrlenW( wszDirectory ) >= directories.m_cchWindows )
	{
		wszDirectory[directories.m_cchWindows] = 0;
		if ( lstrcmpiW( directories.m_wszWindows, wszDirectory ) == 0 )
			entry.m_bInWindowsDirectory = true;
	}

	entry.m_unDirectoryHash =
	    util::hashing::PathHashBytes( reinterpret_cast<const u8 *>( entry.m_szDirectory ), entry.m_cchDirectory );
	entry.m_unBaseNameHash =
	    util::hashing::PathHashBytes( reinterpret_cast<const u8 *>( entry.m_szBaseName ), entry.m_cchBaseName );
}

// @orig: 8B 54 24 ? 8B 44 24 ? 53
bool AppendRecord( ReportBuilder_t &builder, u64 ulBase, u8 unRegionCount, u32 unDirectoryHash, u32 unBaseNameHash,
                   u32 cubImage, ERecordFlags eFlags, u16 unLdrIndex ) noexcept
{
	u8 *pubRecord = builder.m_pubRecordWrite;
	builder.m_pubLastRecord = pubRecord;

	const u32 unTag = HasFlag( eFlags, ERecordFlags::InLdr ) ? ( unLdrIndex & 0xFFFu ) : unRegionCount;
	if ( builder.m_bWideRecords )
	{
		auto *pRecord = reinterpret_cast<ModuleRecord64_t *>( pubRecord );
		pRecord->m_unBaseAndTag = static_cast<u32>( ulBase ) | unTag;
		pRecord->m_unBaseHigh = static_cast<u32>( ulBase >> 32 );
		pRecord->m_unSizeAndFlags = static_cast<u32>( eFlags ) | cubImage;
		pRecord->m_unDirectoryHash = unDirectoryHash;
		pRecord->m_unBaseNameHash = unBaseNameHash;
		builder.m_pubRecordWrite = pubRecord + sizeof( ModuleRecord64_t );
	}
	else
	{
		auto *pRecord = reinterpret_cast<ModuleRecord32_t *>( pubRecord );
		pRecord->m_unBaseAndTag = static_cast<u32>( ulBase ) | unTag;
		pRecord->m_unSizeAndFlags = static_cast<u32>( eFlags ) | cubImage;
		pRecord->m_unDirectoryHash = unDirectoryHash;
		pRecord->m_unBaseNameHash = unBaseNameHash;
		builder.m_pubRecordWrite = pubRecord + sizeof( ModuleRecord32_t );
	}

	return ++builder.m_cRecords != builder.m_cMaxRecords;
}

} // namespace vac::workers::process_memory_map
