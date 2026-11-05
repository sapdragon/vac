// @binary: a07ed54b
#include "internal/pe_file_reader.hpp"
#include "internal/helpers.hpp"
#include "internal/process_reader.hpp"
#include "internal/types.hpp"
#include "bootstrap/bootstrap.hpp"
#include "crt/intrinsics.hpp"
#include "file/file.hpp"
#include "pe/pe.hpp"

namespace vac::workers::system_info
{

namespace
{

constexpr u32 k_cchNameBuffer = 256;

// @orig: 56 6A ? 8B F1 68
char *ClearString( char *pszString ) noexcept
{
	pszString[0] = 0;
	return pszString;
}

} // namespace

// @orig: 53 33 DB 56 8B F1
CPeFileReader::CPeFileReader() noexcept
{
	// @note / sapdragon: m_ulMemoryBase stays uninitialized. only the file path runs here, so nothing reads it
	m_hFile = INVALID_HANDLE_VALUE;
	m_cubWindow = 0;
	m_ulWindowBase = 0;
	m_ibCursor = 0;
	m_ulRangeStart = 0;
	m_ulRangeEnd = 0;
	m_hProcess = nullptr;
	m_ulImageBase = 0;
	m_rgunUnused2140[2] = 0;
	m_pSections = nullptr;
	m_ppSectionData = nullptr;
	m_cExportNames = 0;
	m_ppszExportNames = nullptr;
	m_punExportFunctions = nullptr;
	m_pUnused2690 = nullptr;
	m_cForwarderLibraries = 0;
	m_unUnused2694 = 0;
	m_szExportName[0] = 0;
	m_unUnused2578 = 0;
	m_rgunUnused2140[0] = 0;
	m_rgunUnused2140[1] = 0;
	m_unUnused214C = 0;
	m_bPe64 = 0;
	memset( m_rgpszForwarderLibraries, 0, sizeof( m_rgpszForwarderLibraries ) );
	m_unUnused257C = 0;
	m_unUnused2474 = 0;
	m_unUnused272C = 0;
}

// @orig: 56 8B F1 8B 86
void CPeFileReader::Close() noexcept
{
	if ( IsOpen() )
	{
		g_pImports->CloseHandle( m_hFile );
		m_hFile = INVALID_HANDLE_VALUE;
	}
	m_cubWindow = 0;
	m_ulWindowBase = 0;
	m_ibCursor = 0;
	m_ulRangeStart = 0;
	m_ulRangeEnd = 0;
	m_hProcess = nullptr;
}

// @orig: 8B 81 ? ? ? ? 0B 81
void CPeFileReader::SetMemoryRangeEnd( u32 ulRangeEnd ) noexcept
{
	if ( m_ulMemoryBase && ( !m_hProcess || m_hProcess == INVALID_HANDLE_VALUE ) )
	{
		m_ulRangeStart = 0;
		m_ulRangeEnd = ulRangeEnd;
	}
}

// @orig: 56 8B F1 E8 ? ? ? ? 8B 44 24
bool CPeFileReader::AttachFile( HANDLE hFile ) noexcept
{
	Close();
	m_hFile = hFile;
	ClearString( m_szPath );
	return IsOpen();
}

// @orig: 51 51 53 55 8B 6C 24
const u8 *CPeFileReader::Read( u32 cubRead ) noexcept
{
	if ( cubRead > k_cubReaderPage )
		return nullptr;

	u32 ibCursor = m_ibCursor;
	const u32 cubWindow = m_cubWindow;
	if ( ibCursor + cubRead >= cubWindow )
	{
		u32 ibFill = 0;
		u32 cubFill;
		bool bFill = true;
		if ( ibCursor + cubRead == cubWindow )
		{
			if ( cubWindow == sizeof( m_rgubWindow ) )
			{
				memcpy( m_rgubWindow, m_rgubWindow + k_cubReaderPage, k_cubReaderPage );
				m_ulWindowBase += k_cubReaderPage;
				ibFill = k_cubReaderPage;
				m_ibCursor -= k_cubReaderPage;
				ibCursor = m_ibCursor;
			}
			cubFill = ibFill;
			bFill = ibFill != 0;
		}
		else if ( cubWindow )
		{
			if ( cubWindow < sizeof( m_rgubWindow ) )
				return nullptr;
			memcpy( m_rgubWindow, m_rgubWindow + k_cubReaderPage, k_cubReaderPage );
			m_ulWindowBase += k_cubReaderPage;
			ibFill = k_cubReaderPage;
			cubFill = k_cubReaderPage;
			m_ibCursor -= k_cubReaderPage;
		}
		else
		{
			cubFill = sizeof( m_rgubWindow );
		}

		if ( bFill )
		{
			u32 cubFilled;
			u64 ulRead = 0;
			if ( m_hFile != INVALID_HANDLE_VALUE )
			{
				g_pImports->ReadFile( m_hFile, m_rgubWindow + ibFill, cubFill, reinterpret_cast<DWORD *>( &ulRead ),
				                      nullptr );
				cubFilled = static_cast<u32>( ulRead );
			}
			else if ( !m_hProcess || m_hProcess == INVALID_HANDLE_VALUE )
			{
				const u32 ulFill = static_cast<u32>( m_ulWindowBase ) + ibFill;
				if ( m_ulRangeEnd || m_ulRangeStart )
				{
					if ( ulFill >= m_ulRangeStart )
					{
						if ( static_cast<u64>( ulFill + cubFill ) > m_ulRangeEnd )
							cubFill = static_cast<u32>( m_ulRangeEnd ) - ulFill;
					}
					else
					{
						cubFill = 0;
					}
				}
				memcpy( m_rgubWindow + ibFill,
				        reinterpret_cast<const void *>(
				            static_cast<uptr>( static_cast<u32>( m_ulWindowBase + m_ulMemoryBase ) + ibFill ) ),
				        cubFill );
				cubFilled = cubFill;
			}
			else
			{
				const u64 ulAddress = m_ulWindowBase + m_ulMemoryBase + ibFill;
				ReadVirtualMemoryAuto( m_hProcess, ulAddress, m_rgubWindow + ibFill, cubFill, &ulRead );
				cubFilled = static_cast<u32>( ulRead );
				if ( !ulRead && cubFill > k_cubReaderPage )
				{
					ReadVirtualMemoryAuto( m_hProcess, ulAddress, m_rgubWindow + ibFill, k_cubReaderPage, &ulRead );
					cubFilled = static_cast<u32>( ulRead );
					if ( !ulRead )
						return nullptr;
				}
			}
			ibCursor = m_ibCursor;
			m_cubWindow = cubFilled + ibFill;
		}

		if ( ibCursor + cubRead > m_cubWindow )
			return nullptr;
	}

	m_ibCursor = ibCursor + cubRead;
	return m_rgubWindow + ibCursor;
}

// @orig: 51 51 55 56 33 F6
bool CPeFileReader::ReadBytes( void *pDst, u32 cubRead ) noexcept
{
	u32 ibDone = 0;
	if ( !cubRead )
		return true;

	for ( ;; )
	{
		u32 cubChunk = cubRead - ibDone;
		if ( cubChunk > k_cubReaderPage )
			cubChunk = k_cubReaderPage;
		const u8 *pubChunk = Read( cubChunk );
		if ( !pubChunk )
			return false;
		memcpy( static_cast<u8 *>( pDst ) + ibDone, pubChunk, cubChunk );
		ibDone += cubChunk;
		if ( ibDone == cubRead )
			return true;
	}
}

// @orig: 51 53 55 56 57 6A
i32 CPeFileReader::ReadString( char *pszDst, u32 cchDst ) noexcept
{
	u32 iChar = 0;
	for ( const u8 *pubChar = Read( 1 ); pubChar; pubChar = Read( 1 ) )
	{
		if ( !*pubChar )
			break;
		pszDst[iChar] = static_cast<char>( *pubChar );
		if ( ++iChar == cchDst )
		{
			pszDst[cchDst - 1] = 0;
			return -1;
		}
	}
	pszDst[iChar] = 0;
	return static_cast<i32>( iChar );
}

// @orig: 55 8B EC 83 EC ? 56
bool CPeFileReader::Seek( u32 ibOffset, bool bForce ) noexcept
{
	if ( !bForce )
	{
		if ( m_ulWindowBase + m_ibCursor == ibOffset )
			return true;
		if ( ibOffset >= m_ulWindowBase && ibOffset < m_ulWindowBase + m_cubWindow )
		{
			m_ibCursor = ibOffset - static_cast<u32>( m_ulWindowBase );
			return true;
		}
	}

	m_ibCursor = ibOffset % k_cubReaderPage;
	m_ulWindowBase = ibOffset - m_ibCursor;
	m_cubWindow = 0;
	if ( IsOpen() &&
	     ( static_cast<u32>( m_ulWindowBase ) !=
	           g_pImports->SetFilePointer( m_hFile, static_cast<LONG>( m_ulWindowBase ), nullptr, FILE_BEGIN ) ||
	       m_ulWindowBase >> 32 ) )
	{
		Close();
		return false;
	}
	return true;
}

// @orig: 81 EC ? ? ? ? 53 55 56 57
EScanStatus CPeFileReader::ParseExports() noexcept
{
	const IMAGE_DATA_DIRECTORY &directory = m_bPe64 ? m_OptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
	                                                : m_OptionalHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	u32 unRvaDelta = 0;
	const IMAGE_SECTION_HEADER *pSection =
	    pe::FindSectionByRva( m_pSections, m_FileHeader.NumberOfSections, directory.VirtualAddress );
	if ( pSection && IsOpen() )
		unRvaDelta = pSection->VirtualAddress - pSection->PointerToRawData;

	if ( !Seek( directory.VirtualAddress - unRvaDelta, false ) )
		return EScanStatus::SeekFailed;

	const u32 unDirectoryStart = directory.VirtualAddress;
	const u32 unDirectoryEnd = directory.VirtualAddress + directory.Size;

	IMAGE_EXPORT_DIRECTORY exportDirectory;
	if ( !ReadBytes( &exportDirectory, sizeof( exportDirectory ) ) )
		return EScanStatus::ReadFailed;

	if ( Seek( exportDirectory.Name - unRvaDelta, false ) )
		(void)ReadString( m_szExportName, sizeof( m_szExportName ) );

	const i32 cFunctions = static_cast<i32>( exportDirectory.NumberOfFunctions );
	if ( !cFunctions )
		return EScanStatus::Ok;

	m_cExportNames = static_cast<i32>( exportDirectory.NumberOfNames );
	if ( m_cExportNames > cFunctions )
		return EScanStatus::BadOptionalHeader;

	u16 *punOrdinals = static_cast<u16 *>( HeapAllocate( 2 * m_cExportNames ) );
	if ( !punOrdinals )
		return EScanStatus::AllocFailed;

	EScanStatus eStatus = EScanStatus::Ok;
	u32 *punNameRvas = nullptr;
	char szName[260];
	u32 *punFunctions = static_cast<u32 *>( HeapAllocate( 4 * cFunctions ) );
	if ( !punFunctions )
	{
		eStatus = EScanStatus::AllocFailed;
	}
	else if ( !Seek( exportDirectory.AddressOfFunctions - unRvaDelta, false ) )
	{
		eStatus = EScanStatus::SeekFailed;
	}
	else if ( !ReadBytes( punFunctions, 4 * cFunctions ) )
	{
		eStatus = EScanStatus::ReadFailed;
	}
	else
	{
		const u32 cubNameTable = 4 * m_cExportNames;
		m_ppszExportNames = static_cast<char **>( HeapAllocate( cubNameTable ) );
		memset( m_ppszExportNames, 0, cubNameTable );
		punNameRvas = static_cast<u32 *>( HeapAllocate( cubNameTable ) );
		if ( !punNameRvas )
		{
			eStatus = EScanStatus::AllocFailed;
		}
		else if ( !Seek( exportDirectory.AddressOfNames - unRvaDelta, false ) )
		{
			eStatus = EScanStatus::SeekFailed;
		}
		else if ( !ReadBytes( punNameRvas, cubNameTable ) )
		{
			eStatus = EScanStatus::ReadFailed;
		}
		else
		{
			m_punExportFunctions = static_cast<u32 *>( HeapAllocate( cubNameTable ) );
			memset( m_punExportFunctions, 0, cubNameTable );
			if ( !Seek( exportDirectory.AddressOfNameOrdinals - unRvaDelta, false ) )
				eStatus = EScanStatus::SeekFailed;
			else if ( !ReadBytes( punOrdinals, 2 * m_cExportNames ) )
				eStatus = EScanStatus::ReadFailed;
		}
	}

	if ( eStatus == EScanStatus::Ok )
	{
		for ( i32 iName = 0; iName < m_cExportNames; ++iName )
		{
			if ( !Seek( punNameRvas[iName] - unRvaDelta, false ) )
			{
				eStatus = EScanStatus::SeekFailed;
				break;
			}

			const i32 cchName = ReadString( szName, k_cchNameBuffer );
			if ( cchName < 0 )
			{
				eStatus = EScanStatus::ReadFailed;
				break;
			}

			m_ppszExportNames[iName] = static_cast<char *>( HeapAllocate( cchName + 1 ) );
			memcpy( m_ppszExportNames[iName], szName, cchName + 1 );

			m_punExportFunctions[iName] = punFunctions[punOrdinals[iName]];
			const u32 unFunctionRva = m_punExportFunctions[iName];
			if ( unFunctionRva >= unDirectoryStart && unFunctionRva < unDirectoryEnd )
				m_punExportFunctions[iName] = 0;
		}
	}

	if ( eStatus == EScanStatus::Ok )
	{
		i32 iFunction = 0;
		u16 unFunction = 0;
		while ( iFunction < cFunctions )
		{
			const u32 unFunctionRva = punFunctions[iFunction];
			if ( unFunctionRva >= unDirectoryStart && unFunctionRva < unDirectoryEnd )
			{
				if ( !Seek( unFunctionRva - unRvaDelta, false ) )
				{
					eStatus = EScanStatus::SeekFailed;
					break;
				}

				i32 iDot = ReadString( szName, k_cchNameBuffer );
				for ( ; iDot > 0; --iDot )
				{
					if ( szName[iDot] == '.' )
					{
						szName[iDot] = 0;
						break;
					}
				}
				if ( !iDot )
				{
					eStatus = EScanStatus::ReadFailed;
					break;
				}

				memcpy( &szName[iDot], ".dll", 5 );

				bool bKnown = false;
				for ( i32 iLibrary = 0; iLibrary < m_cForwarderLibraries; ++iLibrary )
				{
					if ( !CompareBoundedNoCase( m_rgpszForwarderLibraries[iLibrary], szName ) )
					{
						bKnown = true;
						break;
					}
				}
				if ( !bKnown )
				{
					// @note / sapdragon: no bound on the table. valve bug, keep it
					const u32 cubCopy = iDot + 5;
					m_rgpszForwarderLibraries[m_cForwarderLibraries] = static_cast<char *>( HeapAllocate( cubCopy ) );
					memcpy( m_rgpszForwarderLibraries[m_cForwarderLibraries], szName, cubCopy );
					++m_cForwarderLibraries;
				}
			}

			// @note / sapdragon: the counter is 16 bits, so a table over 65535 entries never ends
			iFunction = ++unFunction;
		}
	}

	HeapRelease( punOrdinals );
	if ( punFunctions )
		HeapRelease( punFunctions );
	if ( punNameRvas )
		HeapRelease( punNameRvas );
	return eStatus;
}

// @orig: 83 EC ? 53 55 56 57 BD
EScanStatus CPeFileReader::ParseHeaders() noexcept
{
	SetMemoryRangeEnd( k_cubReaderPage );

	if ( !ReadBytes( &m_DosHeader, sizeof( m_DosHeader ) ) )
		return EScanStatus::ReadFailed;
	if ( m_DosHeader.e_magic != IMAGE_DOS_SIGNATURE )
		return EScanStatus::BadImage;
	if ( !ReadBytes( m_rgubDosStub, sizeof( m_rgubDosStub ) ) )
		return EScanStatus::ReadFailed;
	if ( !Seek( m_DosHeader.e_lfanew, false ) )
		return EScanStatus::SeekFailed;

	u32 unSignature;
	if ( !ReadBytes( &unSignature, sizeof( unSignature ) ) )
		return EScanStatus::ReadFailed;
	if ( unSignature != IMAGE_NT_SIGNATURE )
		return EScanStatus::BadImage;

	if ( !ReadBytes( &m_RawFileHeader, sizeof( m_RawFileHeader ) ) )
		return EScanStatus::ReadFailed;
	memcpy( &m_FileHeader, &m_RawFileHeader, sizeof( m_FileHeader ) );

	if ( ( m_FileHeader.Machine != IMAGE_FILE_MACHINE_I386 && m_FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ) ||
	     m_FileHeader.NumberOfSections > 0x40 )
	{
		return EScanStatus::BadImage;
	}

	if ( m_FileHeader.SizeOfOptionalHeader == sizeof( m_OptionalHeader64 ) )
	{
		if ( !ReadBytes( &m_OptionalHeader64, sizeof( m_OptionalHeader64 ) ) )
			return EScanStatus::ReadFailed;
		if ( m_OptionalHeader64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC )
			return EScanStatus::BadOptionalHeader;
		m_bPe64 = 1;
	}
	else if ( m_FileHeader.SizeOfOptionalHeader == sizeof( m_OptionalHeader32 ) )
	{
		if ( !ReadBytes( &m_OptionalHeader32, sizeof( m_OptionalHeader32 ) ) )
			return EScanStatus::ReadFailed;
		if ( m_OptionalHeader32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC )
			return EScanStatus::BadOptionalHeader;
	}
	else
	{
		return EScanStatus::BadOptionalHeader;
	}

	const u32 cSections = m_FileHeader.NumberOfSections;
	m_pSections = static_cast<IMAGE_SECTION_HEADER *>( HeapAllocate( sizeof( IMAGE_SECTION_HEADER ) * cSections ) );
	for ( u32 iSection = 0; iSection < cSections; ++iSection )
	{
		if ( !ReadBytes( &m_pSections[iSection], sizeof( IMAGE_SECTION_HEADER ) ) )
			return EScanStatus::ReadFailed;
	}

	m_ulImageBase = m_bPe64 ? m_OptionalHeader64.ImageBase : m_OptionalHeader32.ImageBase;
	SetMemoryRangeEnd( 0 );
	return EScanStatus::Ok;
}

// @orig: 51 56 8B F1 E8
EScanStatus CPeFileReader::Open( HANDLE hFile ) noexcept
{
	Release();
	if ( AttachFile( hFile ) )
		return Load();
	return EScanStatus::OpenFailed;
}

// @orig: 51 53 55 56 8B F1
EScanStatus CPeFileReader::Load() noexcept
{
	if ( !IsOpen() )
		return EScanStatus::NoFile;

	const EScanStatus eStatus = ParseHeaders();
	if ( eStatus != EScanStatus::Ok )
	{
		Release();
		return eStatus;
	}

	u32 ibSectionsEnd = 0;
	for ( u32 iSection = 0; iSection < m_FileHeader.NumberOfSections; ++iSection )
	{
		const u32 ibEnd = m_pSections[iSection].PointerToRawData + m_pSections[iSection].SizeOfRawData;
		if ( ibEnd > ibSectionsEnd )
			ibSectionsEnd = ibEnd;
	}

	const u32 cubFile = file::GetFileSizeOrZero( g_pImports, m_hFile );
	const u32 cubAlignment = m_bPe64 ? m_OptionalHeader64.SectionAlignment : m_OptionalHeader32.SectionAlignment;
	if ( ibSectionsEnd < cubFile )
	{
		++m_FileHeader.NumberOfSections;
		const u32 cubExtra = cubFile - ibSectionsEnd;
		m_pSections = static_cast<IMAGE_SECTION_HEADER *>(
		    HeapResize( m_pSections, sizeof( IMAGE_SECTION_HEADER ) * m_FileHeader.NumberOfSections ) );

		IMAGE_SECTION_HEADER *pExtra = &m_pSections[m_FileHeader.NumberOfSections - 1];
		const IMAGE_SECTION_HEADER *pLast = &m_pSections[m_FileHeader.NumberOfSections - 2];

		const u32 cubLastRaw = pLast->SizeOfRawData;
		u32 cubLastVirtual = pLast->Misc.VirtualSize;
		if ( cubLastVirtual < cubLastRaw )
			cubLastVirtual = cubAlignment + cubLastRaw - 1 - ( cubAlignment + cubLastRaw - 1 ) % cubAlignment;
		const u32 unNextRva = cubAlignment + cubLastVirtual + pLast->VirtualAddress - 1;

		memset( pExtra, 0, sizeof( IMAGE_SECTION_HEADER ) );
		pExtra->PointerToRawData = ibSectionsEnd;
		pExtra->Characteristics = IMAGE_SCN_MEM_DISCARDABLE;
		pExtra->SizeOfRawData = cubExtra;
		pExtra->VirtualAddress = unNextRva - unNextRva % cubAlignment;
		pExtra->Misc.VirtualSize = cubAlignment + cubExtra - 1 - ( cubAlignment + cubExtra - 1 ) % cubAlignment;
		memcpy( pExtra->Name, ".extra", 7 );
	}
	return EScanStatus::Ok;
}

// @orig: 53 56 57 8B F1
void CPeFileReader::Release() noexcept
{
	Close();

	if ( m_pSections )
		HeapRelease( m_pSections );

	if ( m_cExportNames > 0 )
	{
		if ( m_ppszExportNames )
		{
			for ( i32 iName = 0; iName < m_cExportNames; ++iName )
			{
				if ( m_ppszExportNames[iName] )
					HeapRelease( m_ppszExportNames[iName] );
			}
			HeapRelease( m_ppszExportNames );
		}
		if ( m_punExportFunctions )
			HeapRelease( m_punExportFunctions );
	}

	for ( i32 iLibrary = 0; iLibrary < m_cForwarderLibraries; ++iLibrary )
		HeapRelease( m_rgpszForwarderLibraries[iLibrary] );

	if ( m_pUnused2690 )
		HeapRelease( m_pUnused2690 );

	if ( m_ppSectionData )
	{
		for ( u32 iSection = 0; iSection < m_FileHeader.NumberOfSections; ++iSection )
		{
			if ( m_ppSectionData[iSection] )
				HeapRelease( m_ppSectionData[iSection] );
		}
		HeapRelease( m_ppSectionData );
	}

	m_ulImageBase = 0;
	m_rgunUnused2140[2] = 0;
	m_pSections = nullptr;
	m_ppSectionData = nullptr;
	m_cExportNames = 0;
	m_ppszExportNames = nullptr;
	m_punExportFunctions = nullptr;
	m_cForwarderLibraries = 0;
	m_pUnused2690 = nullptr;
	m_unUnused2694 = 0;
	m_szExportName[0] = 0;
	m_unUnused2578 = 0;
	m_rgunUnused2140[0] = 0;
	m_rgunUnused2140[1] = 0;
	m_unUnused214C = 0;
	m_bPe64 = 0;
	memset( m_rgpszForwarderLibraries, 0, sizeof( m_rgpszForwarderLibraries ) );
	m_unUnused257C = 0;
}

} // namespace vac::workers::system_info
