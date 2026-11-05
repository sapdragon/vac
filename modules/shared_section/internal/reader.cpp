// @binary: 2794a04
#include "internal/types.hpp"
#include "crt/intrinsics.hpp"
#include "util/xor_string.hpp"

namespace vac::workers::shared_section
{

namespace
{

constexpr u8 k_unStringKey = 0x13;
constexpr u32 k_cubDirectoryBufferStep = 1024;

// @note / sapdragon: only wdm.h has these two, same names here
constexpr ACCESS_MASK DIRECTORY_QUERY = 0x0001;
constexpr ACCESS_MASK DIRECTORY_TRAVERSE = 0x0002;

using PfnOpenFileMappingW_t = HANDLE( WINAPI * )( DWORD, BOOL, LPCWSTR );
using PfnMapViewOfFile_t = LPVOID( WINAPI * )( HANDLE, DWORD, DWORD, DWORD, SIZE_T );
using PfnUnmapViewOfFile_t = BOOL( WINAPI * )( LPCVOID );

struct ObjectDirectoryEntry_t
{
	UNICODE_STRING m_Name;
	UNICODE_STRING m_TypeName;
};

// @orig: 55 8B EC 83 E4 ? 83 EC
HANDLE FindSection( const wchar_t *pwszDirectoryType, const wchar_t *pwszWanted, HANDLE hRoot, UNICODE_STRING *pPath,
                    const SystemImports_t *pImports ) noexcept
{
	OBJECT_ATTRIBUTES attributes{};
	attributes.Length = sizeof( attributes );
	attributes.RootDirectory = hRoot;
	attributes.ObjectName = pPath;
	attributes.Attributes = OBJ_CASE_INSENSITIVE;

	HANDLE hDirectory = nullptr;
	HANDLE hResult = nullptr;
	u8 *pubBuffer = nullptr;

	if ( pImports->NtOpenDirectoryObject( &hDirectory, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &attributes ) >= 0 )
	{
		u32 cubBuffer = k_cubDirectoryBufferStep;
		pubBuffer = static_cast<u8 *>( pImports->HeapAlloc( pImports->GetProcessHeap(), 0, cubBuffer ) );
		if ( pubBuffer )
		{
			ULONG unContext = 0;
			for ( ;; )
			{
				const NTSTATUS nStatus = pImports->NtQueryDirectoryObject( hDirectory, pubBuffer, cubBuffer, TRUE,
				                                                           FALSE, &unContext, nullptr );
				if ( nStatus < 0 )
				{
					if ( nStatus == STATUS_BUFFER_TOO_SMALL )
					{
						pImports->HeapFree( pImports->GetProcessHeap(), 0, pubBuffer );
						cubBuffer += k_cubDirectoryBufferStep;
						pubBuffer =
						    static_cast<u8 *>( pImports->HeapAlloc( pImports->GetProcessHeap(), 0, cubBuffer ) );
						if ( pubBuffer )
							continue;
					}
					break;
				}

				auto *pEntry = reinterpret_cast<ObjectDirectoryEntry_t *>( pubBuffer );
				if ( lstrcmpiW( pEntry->m_TypeName.Buffer, pwszDirectoryType ) == 0 )
				{
					hResult = FindSection( pwszDirectoryType, pwszWanted, hDirectory, &pEntry->m_Name, pImports );
					if ( hResult )
						break;
				}
				else if ( lstrcmpiW( pEntry->m_Name.Buffer, pwszWanted ) == 0 )
				{
					attributes.RootDirectory = hDirectory;
					attributes.ObjectName = &pEntry->m_Name;
					if ( pImports->NtOpenSection( &hResult, SECTION_MAP_READ, &attributes ) < 0 )
						hResult = nullptr;
					break;
				}
			}
		}
	}

	if ( hDirectory )
		pImports->CloseHandle( hDirectory );
	if ( pubBuffer )
		pImports->HeapFree( pImports->GetProcessHeap(), 0, pubBuffer );
	return hResult;
}

} // namespace

// @orig: inlined
void FormatMappingName( u32 unIdentifier, wchar_t *pwszName ) noexcept
{
	auto wszFormat = util::MakeXorString<k_unStringKey>( L"{%02xDEDF05-86E9-%02x17-9E36-1D94%02x334DFA-A3%02x4421}" );
	wszFormat.Decode();

	const auto *pubIdentifier = reinterpret_cast<const u8 *>( &unIdentifier );
	wsprintfW( pwszName, wszFormat.Get(), pubIdentifier[0], pubIdentifier[3], pubIdentifier[2], pubIdentifier[1] );
}

// @orig: inlined
void ReadMapping( const Input_t &input, Report_t &report, const SystemImports_t *pImports ) noexcept
{
	auto szKernel32 = util::MakeXorString<k_unStringKey>( "kernel32.dll" );
	auto szOpenFileMappingW = util::MakeXorString<k_unStringKey>( "OpenFileMappingW" );
	auto szMapViewOfFile = util::MakeXorString<k_unStringKey>( "MapViewOfFile" );
	auto szUnmapViewOfFile = util::MakeXorString<k_unStringKey>( "UnmapViewOfFile" );
	auto wszDirectory = util::MakeXorString<k_unStringKey>( L"Directory" );
	szKernel32.Decode();
	szOpenFileMappingW.Decode();
	szMapViewOfFile.Decode();
	szUnmapViewOfFile.Decode();
	wszDirectory.Decode();

	const HMODULE hKernel32 = pImports->LoadLibraryExA( szKernel32.Get(), nullptr, 0 );
	if ( !hKernel32 )
	{
		report.m_eStatus = static_cast<EScanStatus>( pImports->GetLastError() );
		return;
	}

	const auto pfnOpenFileMappingW =
	    reinterpret_cast<PfnOpenFileMappingW_t>( pImports->GetProcAddress( hKernel32, szOpenFileMappingW.Get() ) );
	PfnMapViewOfFile_t pfnMapViewOfFile = nullptr;
	PfnUnmapViewOfFile_t pfnUnmapViewOfFile = nullptr;
	if ( !pfnOpenFileMappingW )
	{
		report.m_eStatus = static_cast<EScanStatus>( pImports->GetLastError() );
		report.m_eFailureLine = EFailureLine::OpenFileMappingMissing;
	}
	else if ( !( pfnMapViewOfFile = reinterpret_cast<PfnMapViewOfFile_t>(
	                 pImports->GetProcAddress( hKernel32, szMapViewOfFile.Get() ) ) ) )
	{
		report.m_eStatus = static_cast<EScanStatus>( pImports->GetLastError() );
		report.m_eFailureLine = EFailureLine::MapViewMissing;
	}
	else if ( !( pfnUnmapViewOfFile = reinterpret_cast<PfnUnmapViewOfFile_t>(
	                 pImports->GetProcAddress( hKernel32, szUnmapViewOfFile.Get() ) ) ) )
	{
		report.m_eStatus = static_cast<EScanStatus>( pImports->GetLastError() );
		report.m_eFailureLine = EFailureLine::UnmapViewMissing;
	}
	else
	{
		wchar_t wszName[48]{};
		FormatMappingName( input.m_unIdentifier, wszName );

		HANDLE hSection = pfnOpenFileMappingW( FILE_MAP_READ, FALSE, wszName );
		if ( !hSection )
		{
			report.m_eStatus = static_cast<EScanStatus>( pImports->GetLastError() );
			if ( report.m_eStatus != EScanStatus::NoFile )
			{
				report.m_eFailureLine = EFailureLine::OpenFailed;
			}
			else
			{
				wchar_t wszRoot[] = L"\\";
				UNICODE_STRING root{ 2, 4, wszRoot };
				hSection = FindSection( wszDirectory.Get(), wszName, nullptr, &root, pImports );
				if ( !hSection )
					report.m_eFailureLine = EFailureLine::SectionNotFound;
			}
		}

		if ( hSection )
		{
			const auto *pubView = static_cast<const u8 *>( pfnMapViewOfFile( hSection, FILE_MAP_READ, 0, 0, 0 ) );
			if ( pubView )
			{
				memcpy( report.m_rgubMappedPayload, pubView + offsetof( Report_t, m_rgubMappedPayload ),
				        sizeof( report.m_rgubMappedPayload ) );
				report.m_unIdentifierA = input.m_unIdentifier;
				report.m_unIdentifierB = input.m_unIdentifier;
				report.m_eStatus = EScanStatus::Ok;
				pfnUnmapViewOfFile( pubView );
			}
			else
			{
				report.m_eStatus = static_cast<EScanStatus>( pImports->GetLastError() );
				report.m_eFailureLine = EFailureLine::MapViewFailed;
			}
			pImports->CloseHandle( hSection );
		}
	}

	pImports->FreeLibrary( hKernel32 );
}

} // namespace vac::workers::shared_section
