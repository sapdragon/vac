// @binary: 8d88e017
#include "core/vac_util.hpp"
#include "crt/intrinsics.hpp"
#include "internal/pe_reader.hpp"
#include "internal/report_builder.hpp"

namespace vac::workers::process_memory_map
{

namespace
{

i32 CurrentStringRatio( const ReportBuilder_t &builder ) noexcept
{
	return builder.m_cubStrings ? GetRecordBytes( builder ) / builder.m_cubStrings : 1000;
}

} // namespace

// @orig: 55 8B EC 83 E4 ? B8 ? ? ? ? E8 ? ? ? ? 33 C0
EScanStatus ScanProcess( const ProcessContext_t &context, Report_t &report, u32 unScanStart, i32 nMaxHashes,
                         i32 nTrimRatio, u32 unMinHashBase, const SystemImports_t *pImports ) noexcept
{
	report.m_cRecords = 0;
	report.m_cubStrings = 0;
	report.m_cHashesPacked = 0;
	report.m_cubCompressed = 0;
	report.m_cubPlain = 0;
	report.m_eFlags =
	    ( report.m_eFlags & static_cast<EReportFlags>( ~static_cast<u16>( EReportFlags::WideRecords ) ) ) |
	    ( context.m_bCross64 ? EReportFlags::WideRecords : EReportFlags::None );

	ReportBuilder_t builder;
	builder.m_cMaxRecords = k_cMaxRecords;
	builder.m_cubStrings = sizeof( builder.m_rgchStrings );
	builder.m_pubRecords = builder.m_rgubRecords;
	builder.m_pubRecordWrite = builder.m_rgubRecords;
	builder.m_pubLastRecord = builder.m_rgubRecords;
	builder.m_pubHashes = builder.m_rgubHashes;
	builder.m_pubHashWrite = builder.m_rgubHashes;
	builder.m_StringEnds.m_prgun = nullptr;
	builder.m_StringEnds.m_cCapacity = 0;
	builder.m_StringEnds.m_c = 0;
	builder.m_cRecords = 0;
	builder.m_cHashes = 0;
	builder.m_bWideRecords = context.m_bCross64;
	builder.m_cMaxHashes = nMaxHashes < k_cMaxHashes ? nMaxHashes : k_cMaxHashes;
	builder.m_ulMinHashBase = unMinHashBase;

	StringTable_t directoryTable;
	StringTable_t baseNameTable;
	InitStringTable( directoryTable );
	InitStringTable( baseNameTable );

	report.m_unScanStart = unScanStart;
	report.m_cLdrModules = static_cast<u16>( context.m_cModules > 0xFFFF ? 0xFFFF : context.m_cModules );
	report.m_cNamedOrPe = 0;
	report.m_cLdrMatches = 0;

	U32Vector_t directoryHashes;
	U32Vector_t baseNameHashes;
	memset( &directoryHashes, 0, sizeof( directoryHashes ) );
	memset( &baseNameHashes, 0, sizeof( baseNameHashes ) );

	AllocationWalk_t walk;
	memset( &walk, 0, sizeof( walk ) );
	walk.m_ulCursor = unScanStart;

	SystemDirectories_t directories;
	pImports->GetWindowsDirectoryW( directories.m_wszWindows, MAX_PATH );
	directories.m_cchWindows = lstrlenW( directories.m_wszWindows );
	pImports->GetSystemDirectoryW( directories.m_wszSystem, MAX_PATH );
	directories.m_cchSystem = lstrlenW( directories.m_wszSystem );

	i32 iNextLdrModule = 0;
	i32 nFoldedPages = 0;
	i32 cCleanRegions = 0;
	bool bPreviousClean = true;

	for ( ;; )
	{
		const LdrModule_t *pLdrModule;
		wchar_t wszLdrPath[MAX_PATH];
		wchar_t wszMappedPath[MAX_PATH];
		for ( ;; )
		{
			if ( !context.m_bCross64 || pImports->NtWow64QueryVirtualMemory64 )
			{
				if ( !WalkAllocation( pImports, context.m_hProcess, walk ) )
					goto scan_done;
			}
			else
			{
				// @note / sapdragon: no 64-bit query on this system, so the LDR list is all there is to walk
				const LdrModule_t *pNext = GetLdrModule( context, iNextLdrModule );
				if ( !pNext )
					goto scan_done;
				++iNextLdrModule;
				walk.m_ulFirstCommitted = pNext->m_ulBase;
				walk.m_First.BaseAddress = pNext->m_ulBase;
				walk.m_First.AllocationBase = pNext->m_ulBase;
				walk.m_cubCommitPrefix = pNext->m_cubImage;
			}

			pLdrModule = FindLdrModuleContaining( context, walk.m_ulFirstCommitted );
			wszLdrPath[0] = 0;
			if ( pLdrModule )
				CopyWideFilled( wszLdrPath, pLdrModule->m_wszFullPath, MAX_PATH );

			wszMappedPath[0] = 0;
			if ( GetMappedFileName( pImports, context.m_hProcess, walk.m_ulFirstCommitted, wszMappedPath ) )
				DevicePathToDosPath( pImports, wszMappedPath );

			if ( ( walk.m_unExecuteProtectUnion & k_unPageExecuteAny ) || pLdrModule )
				break;
		}

		PathEntry_t ldrEntry;
		PathEntry_t mappedEntry;
		ResetPathEntry( ldrEntry );
		ResetPathEntry( mappedEntry );

		u32 unDirectoryHash = 0;
		u32 unBaseNameHash = 0;
		bool bSecondRecord = false;
		if ( wszLdrPath[0] )
		{
			BuildPathEntry( ldrEntry, wszLdrPath, directories, pImports );
			AddString( directoryTable, ldrEntry.m_unDirectoryHash, ldrEntry.m_szDirectory, ldrEntry.m_cchDirectory );
			PushU32( directoryHashes, ldrEntry.m_unDirectoryHash );
			AddString( baseNameTable, ldrEntry.m_unBaseNameHash, ldrEntry.m_szBaseName, ldrEntry.m_cchBaseName );
			PushU32( baseNameHashes, ldrEntry.m_unBaseNameHash );
			unDirectoryHash = ldrEntry.m_unDirectoryHash;
			unBaseNameHash = ldrEntry.m_unBaseNameHash;
		}

		const u32 unLdrDirectoryHash = unDirectoryHash;
		if ( wszMappedPath[0] )
		{
			BuildPathEntry( mappedEntry, wszMappedPath, directories, pImports );
			if ( ldrEntry.m_unDirectoryHash != mappedEntry.m_unDirectoryHash ||
			     ldrEntry.m_unBaseNameHash != mappedEntry.m_unBaseNameHash )
			{
				AddString( directoryTable, mappedEntry.m_unDirectoryHash, mappedEntry.m_szDirectory,
				           mappedEntry.m_cchDirectory );
				PushU32( directoryHashes, mappedEntry.m_unDirectoryHash );
				AddString( baseNameTable, mappedEntry.m_unBaseNameHash, mappedEntry.m_szBaseName,
				           mappedEntry.m_cchBaseName );
				PushU32( baseNameHashes, mappedEntry.m_unBaseNameHash );
				if ( !unDirectoryHash )
					unDirectoryHash = mappedEntry.m_unDirectoryHash;
				if ( unBaseNameHash )
				{
					bSecondRecord = true;
				}
				else
				{
					unBaseNameHash = mappedEntry.m_unBaseNameHash;
					bSecondRecord = unLdrDirectoryHash != 0;
				}
			}
		}

		CPeReader headerReader( pImports );

		ERecordFlags eFlags = ERecordFlags::None;
		u32 cubImage = static_cast<u32>( walk.m_cubCommitPrefix );
		if ( ldrEntry.m_bInSystemDirectory || mappedEntry.m_bInSystemDirectory )
		{
			eFlags = ERecordFlags::SystemDirectory;
			bSecondRecord = false;
		}
		if ( ldrEntry.m_bInWindowsDirectory || mappedEntry.m_bInWindowsDirectory )
			eFlags |= ERecordFlags::WindowsDirectory;

		const LdrModule_t *pPathMatch = nullptr;
		if ( ldrEntry.m_bHasPath )
		{
			eFlags |= ERecordFlags::Named;
			pPathMatch = FindLdrModuleByPath( context, wszLdrPath );
		}
		else if ( mappedEntry.m_bHasPath )
		{
			eFlags |= ERecordFlags::Named;
			pPathMatch = FindLdrModuleByPath( context, wszMappedPath );
		}
		else if ( walk.m_unProtectUnion & PAGE_READONLY )
		{
			eFlags |= ERecordFlags::Odd;
		}

		if ( pLdrModule )
		{
			eFlags |= ERecordFlags::InLdr;
			++report.m_cLdrMatches;
		}
		if ( pPathMatch )
			eFlags |= ERecordFlags::PathInLdr;
		if ( walk.m_unExecuteProtectUnion & PAGE_EXECUTE_READWRITE )
			eFlags |= ERecordFlags::WritableExecute;

		const EScanStatus ePeStatus = headerReader.ParseProcessImage( walk.m_ulFirstCommitted, context.m_hProcess );
		if ( ePeStatus == EScanStatus::BadOptionalHeader )
		{
			eFlags |= ERecordFlags::Odd;
		}
		else if ( ePeStatus == EScanStatus::Ok )
		{
			eFlags |= headerReader.FindSectionByName( ".text" ) ? ERecordFlags::PeImageWithText : ERecordFlags::PeImage;
			if ( !headerReader.FindSectionByName( ".data" ) )
				eFlags |= ERecordFlags::Odd;
			if ( !headerReader.FindSectionByName( ".reloc" ) )
				eFlags |= ERecordFlags::Odd;
			if ( headerReader.IsPe64() )
				eFlags |= ERecordFlags::Pe64;
			if ( headerReader.HasValveStub() )
				eFlags |= ERecordFlags::ValveStub;

			const u32 cubRounded = ( headerReader.GetSizeOfImage() + 0xFFF ) & 0xFFFFF000u;
			if ( cubRounded > cubImage )
				cubImage = cubRounded;
		}

		bool bClean = false;
		if ( !HasFlag( eFlags, ERecordFlags::NotClean ) && walk.m_cubTotal == 0x1000 )
		{
			++cCleanRegions;
			bClean = true;
		}

		if ( bPreviousClean && bClean )
		{
			i32 nPages = static_cast<i32>( walk.m_cRegions ) + nFoldedPages;
			if ( nPages > 255 )
				nPages = 255;
			nFoldedPages = nPages;

			// @note / sapdragon: the first clean region has no record yet, this writes into the unused array and the
			// next append overwrites it. the wide path also wipes the high dword of the base. valve's
			if ( builder.m_bWideRecords )
			{
				auto *pRecord = reinterpret_cast<ModuleRecord64_t *>( builder.m_pubLastRecord );
				if ( !HasFlag( static_cast<ERecordFlags>( pRecord->m_unSizeAndFlags ), ERecordFlags::InLdr ) )
				{
					pRecord->m_unBaseAndTag = ( pRecord->m_unBaseAndTag & 0xFFFFFF00u ) | static_cast<u8>( nPages );
					pRecord->m_unBaseHigh = 0;
				}
			}
			else
			{
				auto *pRecord = reinterpret_cast<ModuleRecord32_t *>( builder.m_pubLastRecord );
				if ( !HasFlag( static_cast<ERecordFlags>( pRecord->m_unSizeAndFlags ), ERecordFlags::InLdr ) )
					pRecord->m_unBaseAndTag = ( pRecord->m_unBaseAndTag & 0xFFFFFF00u ) | static_cast<u8>( nPages );
			}
		}
		else
		{
			bPreviousClean = bClean;
			nFoldedPages = static_cast<i32>( walk.m_cRegions );

			const u16 unLdrIndex = pLdrModule ? static_cast<u16>( pLdrModule->m_unIndex ) : 0;
			const u64 ulBase = walk.m_First.AllocationBase;
			const u8 unRegionCount = static_cast<u8>( walk.m_cRegions );
			bool bRoomLeft = AppendRecord( builder, ulBase, unRegionCount, unDirectoryHash, unBaseNameHash, cubImage,
			                               eFlags, unLdrIndex );
			if ( bSecondRecord && bRoomLeft )
				bRoomLeft =
				    AppendRecord( builder, ulBase, static_cast<u8>( nFoldedPages ), mappedEntry.m_unDirectoryHash,
				                  mappedEntry.m_unBaseNameHash, cubImage, eFlags, unLdrIndex );

			if ( ldrEntry.m_bHasPath || mappedEntry.m_bHasPath || ePeStatus == EScanStatus::Ok )
			{
				if ( builder.m_cHashes < builder.m_cMaxHashes && ulBase > builder.m_ulMinHashBase )
					HashImageIntoTable( builder, context, walk, wszLdrPath[0] ? wszLdrPath : wszMappedPath, pImports );
				++report.m_cNamedOrPe;
			}

			if ( !bRoomLeft )
			{
				headerReader.Release();
				headerReader.CloseSource();
				break;
			}
		}

		headerReader.Release();
		headerReader.CloseSource();
	}

scan_done:
	report.m_cCleanRegions = static_cast<u16>( cCleanRegions > 0xFFFF ? 0xFFFF : cCleanRegions );
	builder.m_cubStrings = 0;
	report.m_cRecordsScanned = builder.m_cRecords;
	report.m_unScanEnd = static_cast<u32>( walk.m_ulQueryAddress );
	report.m_unLastError = walk.m_unLastError;

	const i32 nTrim = nTrimRatio > 0 ? nTrimRatio : 6;
	if ( nTrim < 100 )
		builder.m_cubStrings = PackStrings( baseNameTable, directoryTable, directoryHashes, baseNameHashes,
		                                    builder.m_StringEnds, builder.m_rgchStrings );

	report.m_cHashesPacked = 0;
	report.m_cubCompressed = 0;
	report.m_cRecords = 0;
	report.m_cubStrings = 0;

	i32 cubPlain;
	for ( ;; )
	{
		const i32 cubCompressed = CompressRecords( builder, report.m_rgubCompressed );
		i32 nBudget;
		if ( cubCompressed )
		{
			if ( cubCompressed <= static_cast<i32>( sizeof( report.m_rgubCompressed ) ) )
			{
				report.m_cHashesPacked = static_cast<u8>( builder.m_cHashes );
				report.m_cRecords = static_cast<u16>( builder.m_cRecords );
				report.m_cubStrings = static_cast<u16>( builder.m_cubStrings );
				report.m_cubCompressed = cubCompressed;
				cubPlain = builder.m_cubPlain;
				break;
			}

			const i32 cubUncompressed = GetPlainSize( builder );
			nBudget = ( cubCompressed - static_cast<i32>( sizeof( report.m_rgubCompressed ) ) ) *
			          ( 100 * cubUncompressed / cubCompressed ) / 120;
		}
		else
		{
			nBudget = GetPlainSize( builder ) / 2;
		}

		if ( !nBudget )
			nBudget = 1;
		else if ( nBudget < 0 )
			continue;

		bool bStuck = false;
		for ( ;; )
		{
			i32 nRatio = CurrentStringRatio( builder );
			i32 cubRemoved = 0;

			if ( nRatio <= nTrim )
			{
				while ( nBudget > 0 )
				{
					if ( builder.m_StringEnds.m_c > 0 )
					{
						const i32 cubBefore = builder.m_cubStrings;
						--builder.m_StringEnds.m_c;
						builder.m_cubStrings =
						    static_cast<i32>( builder.m_StringEnds.m_prgun[builder.m_StringEnds.m_c] );
						const i32 cubDelta = cubBefore - builder.m_cubStrings;
						cubRemoved += cubDelta;
						nBudget -= cubDelta;
						nRatio = CurrentStringRatio( builder );
						if ( nRatio <= nTrim )
							continue;
					}
					break;
				}
			}

			if ( nRatio > nTrim )
			{
				// @note / sapdragon: no zero check on the divide. with strings off (trim ratio 100 and up) and a report
				// that doesn't fit, valve's dll dies right here with a divide by zero, and so does this
				i32 nRecordRatio;
				do
				{
					if ( nBudget <= 0 || builder.m_cRecords <= 0 )
						break;
					const i32 cubBefore = GetRecordBytes( builder );
					--builder.m_cRecords;
					const i32 cubAfter = GetRecordBytes( builder );
					cubRemoved += cubBefore - cubAfter;
					nBudget -= cubBefore - cubAfter;
					nRecordRatio = cubAfter / builder.m_cubStrings;
				} while ( nRecordRatio > nTrim );
			}

			if ( !cubRemoved )
			{
				bStuck = true;
				break;
			}
			if ( nBudget <= 0 )
				break;
		}

		if ( bStuck )
		{
			cubPlain = GetPlainSize( builder );
			report.m_eFlags |= EReportFlags::TrimFailed;
			break;
		}
	}

	report.m_cubPlain = cubPlain;
	report.m_cHashes = static_cast<u16>( builder.m_cHashes );
	report.m_cRecordsPacked = builder.m_cRecords;

	util::HeapFree( baseNameHashes.m_prgun );
	util::HeapFree( directoryHashes.m_prgun );
	util::HeapFree( baseNameTable.m_pchStorage );
	util::HeapFree( baseNameTable.m_pEntries );
	util::HeapFree( directoryTable.m_pchStorage );
	util::HeapFree( directoryTable.m_pEntries );
	util::HeapFree( builder.m_StringEnds.m_prgun );
	return EScanStatus::ScanDone;
}

} // namespace vac::workers::process_memory_map
