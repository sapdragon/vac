// @binary: 2023d8c3
#include "internal/string_table.hpp"
#include "internal/types.hpp"
#include "core/vac_util.hpp"
#include "crt/intrinsics.hpp"
#include "util/encoding.hpp"
#include "util/hashing.hpp"
#include "util/strings.hpp"
#include "util/wstr.hpp"

namespace vac::workers::driver_inventory
{

namespace
{

constexpr u32 k_cubServices = 0x10000;
constexpr u32 k_cubConfig = 0x1000;

// @note / sapdragon: DIRECTORY_QUERY, only the driver kit headers have it
constexpr ACCESS_MASK k_unDirectoryQuery = 1;

// @note / sapdragon: hash of the first five bytes of the name: "mpksl", defender's driver with a random suffix
constexpr u32 k_unVersionedFolderHash = 0xDC8AF399;

struct ScratchRow_t
{
	u32 m_unNameHash;
	u32 m_unNameTextHash;
	u32 m_unPathTextHash;
	EDriverEntryFlags m_eFlags;
};

struct ObjectDirectoryEntry_t
{
	UNICODE_STRING m_Name;
	UNICODE_STRING m_TypeName;
};

constexpr char k_szNoPath[] = " ";
constexpr wchar_t k_wszDriverDirectory[] = L"\\Driver";

// @note / sapdragon: variadic in the original, the arguments are a plain va_list on x86
// @orig: 8D 44 24 ? 50 FF 74 24 ? FF 74 24
void FormatGroupPath( wchar_t *pwszOut, const wchar_t *pwszGroup, const wchar_t *pwszDisplayName ) noexcept
{
	const wchar_t *rgpwszArguments[] = { pwszGroup, pwszDisplayName };
	wvsprintfW( pwszOut, L"[%s]\\%s", reinterpret_cast<va_list>( rgpwszArguments ) );
}

// @orig: 0F B7 01 66 85 C0
const wchar_t *FindBackslash( const wchar_t *pwszText ) noexcept
{
	for ( ; *pwszText; ++pwszText )
	{
		if ( *pwszText == L'\\' )
			return pwszText;
	}
	return nullptr;
}

} // namespace

// @orig: 81 EC ? ? ? ? 53 55 33 DB
EScanStatus CollectDriverServiceInventory( DriverInventoryReport_t &report, const SystemImports_t *pImports ) noexcept
{
	EScanStatus eStatus = EScanStatus::Ok;
	SC_HANDLE hService = nullptr;
	HANDLE hDirectory = nullptr;
	ScratchRow_t *pRows = nullptr;
	QUERY_SERVICE_CONFIGW *pConfig = nullptr;
	ENUM_SERVICE_STATUSW *pServices = nullptr;
	DWORD unResume = 0;
	DWORD cubNeeded;
	DWORD cServices;

	// @note / sapdragon: left uninitialized on purpose. the prefix hash below can read stale bytes on short names
	u8 rgubText[260];
	u8 rgubObjectName[128];
	wchar_t wszGroupPath[128];

	StringTable_t pathTable;
	StringTable_t nameTable;
	StringTable_t indexTable;
	InitStringTable( pathTable );
	InitStringTable( nameTable );
	InitStringTable( indexTable );
	HashVector_t pathHashes{};
	HashVector_t nameHashes{};

	SC_HANDLE hManager = pImports->OpenSCManagerA( nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE );
	if ( !hManager )
	{
		eStatus = static_cast<EScanStatus>( pImports->GetLastError() );
		goto cleanup;
	}

	pServices = static_cast<ENUM_SERVICE_STATUSW *>( util::HeapAlloc( k_cubServices ) );
	if ( !pServices )
	{
		eStatus = EScanStatus::NotEnoughMemory;
		goto cleanup;
	}
	memset( pServices, 0, k_cubServices );

	{
		const BOOL bEnumerated = pImports->EnumServicesStatusW( hManager, SERVICE_DRIVER, SERVICE_ACTIVE, pServices,
		                                                        k_cubServices, &cubNeeded, &cServices, &unResume );
		const u32 unEnumError = pImports->GetLastError();
		if ( !bEnumerated && unEnumError != ERROR_MORE_DATA )
		{
			eStatus = static_cast<EScanStatus>( pImports->GetLastError() );
			goto cleanup;
		}
	}

	report.m_cServices = cServices;
	if ( cServices > ARRAYSIZE( report.m_rgEntries ) )
		cServices = ARRAYSIZE( report.m_rgEntries );

	// @note / sapdragon: 32 bytes a service, rows take 16. with zero services the zero-size block still gets object rows
	pRows = static_cast<ScratchRow_t *>( util::HeapAlloc( 32 * cServices ) );
	report.m_cEntries = 0;
	if ( !pRows )
	{
		eStatus = EScanStatus::NotEnoughMemory;
		goto cleanup;
	}

	pConfig = static_cast<QUERY_SERVICE_CONFIGW *>( util::HeapAlloc( k_cubConfig ) );
	if ( !pConfig )
	{
		eStatus = EScanStatus::NotEnoughMemory;
		goto cleanup;
	}

	for ( u32 iService = 0; iService < cServices; ++iService )
	{
		const wchar_t *pwszServiceName = pServices[iService].lpServiceName;
		hService = pImports->OpenServiceW( hManager, pwszServiceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS );
		if ( !hService )
		{
			eStatus = static_cast<EScanStatus>( pImports->GetLastError() );
			goto cleanup;
		}
		if ( !pImports->QueryServiceConfigW( hService, pConfig, k_cubConfig, &cubNeeded ) )
		{
			eStatus = static_cast<EScanStatus>( pImports->GetLastError() );
			goto cleanup;
		}
		pImports->CloseServiceHandle( hService );

		u32 unPathTextHash = 0;
		u32 unNameTextHash = 0;
		wchar_t *pwszPath = pConfig->lpBinaryPathName;
		if ( !*pwszPath )
		{
			FormatGroupPath( wszGroupPath, pConfig->lpLoadOrderGroup, pConfig->lpDisplayName );
			pwszPath = wszGroupPath;
		}

		if ( FindBackslash( pwszPath ) )
		{
			const wchar_t *pwszBase = util::wstr::BaseName( pwszPath );
			if ( pwszBase )
			{
				// @note / sapdragon: writes before the string when the only backslash is the first char. valve's
				pwszPath[pwszBase - pwszPath - 1] = 0;

				util::encoding::WideToUtf8Bounded( pImports, pwszServiceName, reinterpret_cast<char *>( rgubText ),
				                                   sizeof( rgubText ) );
				if ( util::hashing::PathHashBytes( rgubText, 5 ) == k_unVersionedFolderHash )
				{
					wchar_t *pwszSlash = pwszPath + util::wstr::Length( pwszPath ) + 1;
					while ( pwszSlash != pwszPath )
					{
						if ( *--pwszSlash == L'\\' )
						{
							*pwszSlash = 0;
							break;
						}
					}
				}

				util::encoding::WideToUtf8Bounded( pImports, pwszPath, reinterpret_cast<char *>( rgubText ),
				                                   sizeof( rgubText ) );
				u32 cubText = util::StrLenA( reinterpret_cast<const char *>( rgubText ) );
				unPathTextHash = util::hashing::PathHashBytes( rgubText, cubText );
				AddString( pathTable, unPathTextHash, rgubText, cubText );
				PushHash( pathHashes, unPathTextHash );

				util::encoding::WideToUtf8Bounded( pImports, pwszServiceName, reinterpret_cast<char *>( rgubText ),
				                                   sizeof( rgubText ) );
				cubText = util::StrLenA( reinterpret_cast<const char *>( rgubText ) );
				unNameTextHash = util::hashing::PathHashBytes( rgubText, cubText );
				AddString( nameTable, unNameTextHash, rgubText, cubText );
				PushHash( nameHashes, unNameTextHash );
			}
		}

		util::encoding::WideToUtf8Bounded( pImports, pwszServiceName, reinterpret_cast<char *>( rgubText ),
		                                   sizeof( rgubText ) );
		ScratchRow_t &row = pRows[report.m_cEntries];
		row.m_unNameHash =
		    util::hashing::PathHashBytes( rgubText, util::StrLenA( reinterpret_cast<const char *>( rgubText ) ) );
		row.m_unPathTextHash = unPathTextHash;
		row.m_unNameTextHash = unNameTextHash;
		row.m_eFlags = EDriverEntryFlags::Service;
		++report.m_cEntries;
	}

	{
		UNICODE_STRING name;
		name.Length = sizeof( k_wszDriverDirectory ) - sizeof( wchar_t );
		name.MaximumLength = sizeof( k_wszDriverDirectory );
		name.Buffer = const_cast<PWSTR>( k_wszDriverDirectory );

		OBJECT_ATTRIBUTES attributes;
		attributes.Length = sizeof( attributes );
		attributes.RootDirectory = nullptr;
		attributes.ObjectName = &name;
		attributes.Attributes = OBJ_CASE_INSENSITIVE;
		attributes.SecurityDescriptor = nullptr;
		attributes.SecurityQualityOfService = nullptr;

		// @note / sapdragon: the directory handle is never closed. valve's leak
		if ( pImports->NtOpenDirectoryObject( &hDirectory, READ_CONTROL | k_unDirectoryQuery, &attributes ) >= 0 )
		{
			ULONG unContext = 0;
			ULONG cubReturned = 0;
			auto *pObject = reinterpret_cast<ObjectDirectoryEntry_t *>( pConfig );
			BOOLEAN bRestart = TRUE;
			while ( pImports->NtQueryDirectoryObject( hDirectory, pConfig, k_cubConfig, TRUE, bRestart, &unContext,
			                                          &cubReturned ) >= 0 )
			{
				bRestart = FALSE;
				++report.m_cDriverObjects;

				util::encoding::WideToUtf8Bounded( pImports, pObject->m_Name.Buffer,
				                                   reinterpret_cast<char *>( rgubObjectName ),
				                                   sizeof( rgubObjectName ) );
				const u32 unHash = util::hashing::PathHashBytes(
				    rgubObjectName, util::StrLenA( reinterpret_cast<const char *>( rgubObjectName ) ) );

				u32 iRow = 0;
				for ( ; iRow < report.m_cEntries; ++iRow )
				{
					if ( pRows[iRow].m_unNameHash == unHash )
						break;
				}

				if ( iRow < report.m_cEntries )
				{
					pRows[iRow].m_eFlags |= EDriverEntryFlags::DriverObject;
				}
				else if ( report.m_cEntries < ARRAYSIZE( report.m_rgEntries ) )
				{
					ScratchRow_t &row = pRows[report.m_cEntries];
					row.m_unNameHash = unHash;
					row.m_unNameTextHash = unHash;
					AddString( nameTable, unHash, rgubObjectName,
					           util::StrLenA( reinterpret_cast<const char *>( rgubObjectName ) ) );
					PushHash( nameHashes, unHash );

					const u32 cubNoPath = util::StrLenA( k_szNoPath );
					row.m_unPathTextHash =
					    util::hashing::PathHashBytes( reinterpret_cast<const u8 *>( k_szNoPath ), cubNoPath );
					AddString( pathTable, row.m_unPathTextHash, k_szNoPath, cubNoPath );
					PushHash( pathHashes, row.m_unPathTextHash );
					row.m_eFlags = EDriverEntryFlags::DriverObject;
					++report.m_cEntries;
				}
			}
		}
	}

	{
		const i32 cubStrings = static_cast<i32>( sizeof( report.m_rgubEntriesAndStrings ) - 1 -
		                                         sizeof( DriverEntry_t ) * report.m_cEntries );
		u8 *pubStrings =
		    reinterpret_cast<u8 *>( report.m_rgubEntriesAndStrings ) + sizeof( DriverEntry_t ) * report.m_cEntries;
		PackDriverStringTables( nameTable, pathTable, pathHashes, nameHashes, cubStrings, pubStrings );
		pubStrings[cubStrings] = 0;
	}

	hService = nullptr;

	{
		// @note / sapdragon: the emitted flags live in the hash vectors, which skip rows without strings
		u32 iHash = 0;
		for ( u32 iRow = 0; iRow < report.m_cEntries; ++iRow )
		{
			const ScratchRow_t &row = pRows[iRow];
			if ( row.m_unNameTextHash && !nameHashes.m_punData[iHash] )
				AddString( indexTable, row.m_unNameTextHash, nullptr, 0 );
			if ( row.m_unPathTextHash && !pathHashes.m_punData[iHash] )
				AddString( indexTable, row.m_unPathTextHash, nullptr, 0 );

			DriverEntry_t &entry = report.m_rgEntries[iRow];
			entry.m_unNameHash = row.m_unNameHash;
			entry.m_nNameString = static_cast<i16>( FindStringByHash( indexTable, row.m_unNameTextHash ) );
			entry.m_nPathString = static_cast<i16>( FindStringByHash( indexTable, row.m_unPathTextHash ) );
			entry.m_eFlags = row.m_eFlags;

			if ( row.m_unNameTextHash )
				++iHash;
		}
	}

cleanup:
	util::HeapFree( pRows );
	util::HeapFree( pConfig );
	util::HeapFree( pServices );
	pImports->CloseServiceHandle( hService );
	pImports->CloseServiceHandle( hManager );
	if ( nameHashes.m_punData )
		util::HeapFree( nameHashes.m_punData );
	if ( pathHashes.m_punData )
		util::HeapFree( pathHashes.m_punData );
	DestroyStringTable( indexTable );
	DestroyStringTable( nameTable );
	DestroyStringTable( pathTable );
	return eStatus;
}

} // namespace vac::workers::driver_inventory
