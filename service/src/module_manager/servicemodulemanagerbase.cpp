// @binary: 7ebac2a4
#include "module_manager/servicemodulemanagerbase.hpp"
#include "signature/valvesignature.hpp"

#include "crypto/hash/crc32.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace
{

std::string GetExecutableDir()
{
	char szPath[MAX_PATH]{};
	GetModuleFileNameA( nullptr, szPath, MAX_PATH );
	std::string sPath = szPath;
	const size_t ichSlash = sPath.find_last_of( "\\/" );
	return ichSlash == std::string::npos ? std::string( "." ) : sPath.substr( 0, ichSlash );
}

// @orig: 55 8B EC 81 EC ? ? ? ? 8D 85 ? ? ? ? 50
bool CreateTempFileName( std::string *psName )
{
	char szDirectory[MAX_PATH];
	char szName[MAX_PATH];
	if ( !GetTempPathA( MAX_PATH, szDirectory ) || !GetTempFileNameA( szDirectory, "", 0, szName ) )
		return false;
	*psName = szName;
	return true;
}

// @orig: 55 8B EC 83 EC ? 53 56 57 51 8B C4 8D 4D ? C7 00 ? ? ? ? FF 75 ? E8 ? ? ? ? FF 75
bool SaveBufferToFile( const void *pvData, uint32_t cubData, const char *pszName )
{
	FILE *pFile = nullptr;
	if ( fopen_s( &pFile, pszName, "wb" ) != 0 || !pFile )
		return false;
	const bool bWritten = fwrite( pvData, 1, cubData, pFile ) == cubData;
	fclose( pFile );
	return bWritten;
}

bool ReadWholeFile( const std::string &sName, std::vector<uint8_t> *pvecData )
{
	FILE *pFile = nullptr;
	if ( fopen_s( &pFile, sName.c_str(), "rb" ) != 0 || !pFile )
		return false;
	fseek( pFile, 0, SEEK_END );
	const long cubFile = ftell( pFile );
	fseek( pFile, 0, SEEK_SET );
	pvecData->resize( cubFile > 0 ? static_cast<size_t>( cubFile ) : 0 );
	const bool bRead = pvecData->empty() || fread( pvecData->data(), 1, pvecData->size(), pFile ) == pvecData->size();
	fclose( pFile );
	return bRead;
}

int CopyExceptionRecord( const EXCEPTION_POINTERS *pPointers, EXCEPTION_RECORD32 *pRecord )
{
	memcpy( pRecord, pPointers->ExceptionRecord, sizeof( EXCEPTION_RECORD32 ) );
	return EXCEPTION_EXECUTE_HANDLER;
}

} // namespace

// @orig: 55 8B EC 51 0F B6 45
CClientModuleManagerBase::CClientModuleManagerBase() : m_sBaseDir( GetExecutableDir() ) {}

// @orig: 55 8B EC 56 57 8B F9 33 F6
CClientModuleManagerBase::~CClientModuleManagerBase()
{
	for ( auto &[uiCRC32, pModule] : m_mapModules )
	{
		UnloadModuleInternal( pModule );
		delete pModule;
	}
}

uint64_t CClientModuleManagerBase::CurrentMicroSecs() const
{
	return GetTickCount64() * 1000;
}

// @orig: 55 8B EC 56 8B F1 8D 45
DynamicModule_t *CClientModuleManagerBase::FindModule( uint32_t uiCRC32 ) const
{
	const auto it = m_mapModules.find( uiCRC32 );
	return it == m_mapModules.end() ? nullptr : it->second;
}

// @orig: 55 8B EC 83 EC ? 53 56 57 8B 7D ? 8B C1
bool CClientModuleManagerBase::LoadModule( uint32_t uiCRC32, const void *pvModule, uint32_t cubModule )
{
	if ( !uiCRC32 || !cubModule || cubModule > 0xFFFFFF || !pvModule )
		return false;

	if ( FindModule( uiCRC32 ) )
		return true;

	if ( uiCRC32 != vac::crypto::hash::Crc32_t::Of( static_cast<const vac::u8 *>( pvModule ), cubModule ) )
		return false;

	void *pvRawModule = malloc( cubModule );
	if ( !pvRawModule )
		return false;

	auto *pModule = new DynamicModule_t{};
	pModule->m_pRawModule = pvRawModule;
	pModule->m_uiCRC32 = uiCRC32;
	pModule->m_uiRawModuleSize = cubModule;
	pModule->m_ulLastUsedMicroSecs = CurrentMicroSecs();
	memcpy( pvRawModule, pvModule, cubModule );
	m_mapModules.emplace( uiCRC32, pModule );
	return true;
}

// @orig: 55 8B EC 51 8B 45 ? 53 56 57 8B F9 89 45
bool CClientModuleManagerBase::UnloadModule( uint32_t uiCRC32 )
{
	DynamicModule_t *pModule = FindModule( uiCRC32 );
	if ( !pModule )
		return false;

	UnloadModuleInternal( pModule );
	delete pModule;
	m_mapModules.erase( uiCRC32 );
	return true;
}

// @orig: 55 8B EC 56 8B 75 ? 8B 46 ? 85 C0 74 ? 50
void CClientModuleManagerBase::UnloadModuleInternal( DynamicModule_t *pModule )
{
	if ( pModule->m_hModule )
	{
		FreeLibrary( pModule->m_hModule );
		pModule->m_hModule = nullptr;
	}

	if ( !pModule->m_sFileName.empty() )
	{
		DeleteFileA( pModule->m_sFileName.c_str() );
		pModule->m_sFileName.clear();
	}

	if ( pModule->m_pModule )
	{
		UnloadModuleHiddenInternal( pModule->m_pModule );
		pModule->m_pModule = nullptr;
	}

	if ( pModule->m_pRawModule )
	{
		free( pModule->m_pRawModule );
		pModule->m_pRawModule = nullptr;
	}

	pModule->m_pServiceFunction = nullptr;
}

bool CClientModuleManagerBase::BVerifyModule( DynamicModule_t *pModule ) const
{
	if ( m_vecDevelopmentKeys.empty() )
		return VerifyValveSignature( pModule->m_pRawModule, pModule->m_uiRawModuleSize ) == ESignatureResult::Valid;

	std::vector<const char *> vecKeys;
	for ( const std::string &sKey : m_vecDevelopmentKeys )
		vecKeys.push_back( sKey.c_str() );
	return VerifyValveWin32Signature( pModule->m_pRawModule, pModule->m_uiRawModuleSize, vecKeys.data(),
	                                  static_cast<uint32_t>( vecKeys.size() ) ) == ESignatureResult::Valid;
}

// @orig: 55 8B EC 83 EC ? 53 56 8B 75 ? 8B D9 83 7E
bool CClientModuleManagerBase::LoadDynamicModule( DynamicModule_t *pModule, uint32_t unFlags )
{
	if ( pModule->m_pServiceFunction )
		return true;

	if ( !pModule->m_pRawModule || !pModule->m_uiRawModuleSize )
	{
		pModule->m_eLastResult = ECallResult::NoModuleData;
		return false;
	}

	if ( !BVerifyModule( pModule ) )
	{
		UnloadModuleInternal( pModule );
		pModule->m_eLastResult = ECallResult::BadSignature;
		return false;
	}

	if ( unFlags & MF_HIDDEN_MODULE )
	{
		pModule->m_pModule = LoadModuleHiddenInternal( pModule->m_pRawModule, nullptr, true );
		if ( pModule->m_pModule )
		{
			pModule->m_pServiceFunction =
			    reinterpret_cast<PfnServiceFunction_t>( GetProcAddressHidden( pModule->m_pModule, "_runfunc@20" ) );
			if ( !pModule->m_pServiceFunction )
				pModule->m_eLastResult = ECallResult::NoRunFuncHidden;
		}
		else
		{
			pModule->m_eLastResult = ECallResult::LoadFailed;
		}
	}
	else
	{
		pModule->m_eLastResult = ECallResult::None;
		std::string sTempFile;
		if ( !CreateTempFileName( &sTempFile ) )
		{
			pModule->m_eLastResult = ECallResult::TempFileFailed;
		}
		else if ( !SaveBufferToFile( pModule->m_pRawModule, pModule->m_uiRawModuleSize, sTempFile.c_str() ) )
		{
			pModule->m_eLastResult = ECallResult::SaveFailed;
		}
		else
		{
			pModule->m_sFileName = sTempFile;
			pModule->m_hModule = LoadLibraryExA( sTempFile.c_str(), nullptr, 0 );
			if ( pModule->m_hModule )
			{
				pModule->m_pServiceFunction =
				    reinterpret_cast<PfnServiceFunction_t>( GetProcAddress( pModule->m_hModule, "_runfunc@20" ) );
				if ( !pModule->m_pServiceFunction )
					pModule->m_eLastResult = ECallResult::NoRunFuncLoaded;
			}
			else
			{
				pModule->m_eLastResult = ECallResult::LoadFailed;
			}
		}
	}

	if ( !pModule->m_pServiceFunction )
	{
		UnloadModuleInternal( pModule );
		return false;
	}

	pModule->m_ulLastUsedMicroSecs = CurrentMicroSecs();
	if ( pModule->m_pRawModule )
	{
		free( pModule->m_pRawModule );
		pModule->m_pRawModule = nullptr;
	}
	return true;
}

// @orig: 55 8B EC 6A ? 68 ? ? ? ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 64 89 25 ? ? ? ? 83 EC ? 53 56 57 89 65 ? 8B F1
ECallResult CClientModuleManagerBase::CallFunction( uint32_t uiCRC32, uint32_t unFlags, int nRequest,
                                                    const void *pvInput, uint32_t cubInput, void *pvOutput,
                                                    uint32_t cubOutput, uint32_t *pcubRequired )
{
	*pcubRequired = 0;
	DynamicModule_t *pModule = FindModule( uiCRC32 );
	if ( !pModule )
		return ECallResult::ModuleNotFound;
	if ( cubOutput < sizeof( ExceptionResponse_t ) )
		return ECallResult::OutputTooSmall;
	if ( !LoadDynamicModule( pModule, unFlags ) )
		return pModule->m_eLastResult;

	*pcubRequired = cubOutput;
	EXCEPTION_RECORD32 record{};
	__try
	{
		pModule->m_eLastResult = static_cast<ECallResult>(
		    pModule->m_pServiceFunction( nRequest, pvInput, cubInput, pvOutput, pcubRequired ) );
	}
	__except ( CopyExceptionRecord( GetExceptionInformation(), &record ) )
	{
		auto *pResponse = static_cast<ExceptionResponse_t *>( pvOutput );
		pResponse->m_pServiceFunction = pModule->m_pServiceFunction;
		pResponse->m_unReserved = 0;
		pResponse->m_Record = record;
		pModule->m_eLastResult = ECallResult::Exception;
		*pcubRequired = sizeof( ExceptionResponse_t );
	}

	pModule->m_ulLastUsedMicroSecs = CurrentMicroSecs();
	const ECallResult eResult = pModule->m_eLastResult;
	if ( unFlags & MF_UNLOAD_AFTER_EXEC )
		UnloadModule( uiCRC32 );
	return eResult;
}

// @orig: 55 8B EC 6A ? 68 ? ? ? ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 64 89 25 ? ? ? ? 83 EC ? 53 56 57 89 65 ? 8B F9
ECallResult CClientModuleManagerBase::CallFunctionAsyncInternal( uint32_t uiCRC32, uint32_t unFlags, int nRequest,
                                                                 const void *pvInput, uint32_t cubInput,
                                                                 void **ppvOutput, uint32_t *pcubOutput )
{
	DynamicModule_t *pModule = FindModule( uiCRC32 );
	if ( !pModule )
	{
		*pcubOutput = 0;
		return ECallResult::ModuleNotFound;
	}

	uint32_t cubRequired = *pcubOutput;
	if ( cubRequired < sizeof( ExceptionResponse_t ) )
		cubRequired = sizeof( ExceptionResponse_t );
	*ppvOutput = malloc( cubRequired );

	if ( LoadDynamicModule( pModule, unFlags ) )
	{
		if ( *ppvOutput )
		{
			memset( *ppvOutput, 0, cubRequired );
			EXCEPTION_RECORD32 record{};
			__try
			{
				pModule->m_eLastResult = static_cast<ECallResult>(
				    pModule->m_pServiceFunction( nRequest, pvInput, cubInput, *ppvOutput, &cubRequired ) );
			}
			__except ( CopyExceptionRecord( GetExceptionInformation(), &record ) )
			{
				auto *pResponse = static_cast<ExceptionResponse_t *>( *ppvOutput );
				pResponse->m_pServiceFunction = pModule->m_pServiceFunction;
				pResponse->m_unReserved = 0;
				pResponse->m_Record = record;
				pModule->m_eLastResult = ECallResult::Exception;
				*pcubOutput = sizeof( ExceptionResponse_t );
			}
		}
		else
		{
			*pcubOutput = 0;
			pModule->m_eLastResult = ECallResult::AllocFailed;
		}
	}
	else
	{
		*pcubOutput = 0;
	}

	if ( pModule->m_eLastResult == ECallResult::OK && cubRequired > *pcubOutput )
	{
		pModule->m_eLastResult = ECallResult::OutputTooLarge;
		cubRequired = 0;
	}

	if ( pModule->m_eLastResult != ECallResult::Exception )
	{
		pModule->m_ulLastUsedMicroSecs = CurrentMicroSecs();
		*pcubOutput = cubRequired;
	}

	const ECallResult eResult = pModule->m_eLastResult;
	if ( unFlags & MF_UNLOAD_AFTER_EXEC )
		UnloadModule( uiCRC32 );
	return eResult;
}

// @orig: 55 8B EC 81 EC ? ? ? ? 56 57 B8
ECallResult CClientModuleManagerBase::CallFunctionAsyncInternal_LegacyCompat( uint32_t uiCRC32, uint32_t unFlags,
                                                                              int nRequest, uint32_t unFile,
                                                                              const void *pvInput, uint32_t cubInput,
                                                                              void **ppvOutput, uint32_t *pcubOutput )
{
	const uint32_t cubOutputLimit = *pcubOutput;
	*pcubOutput = 0;
	DynamicModule_t *pModule = FindModule( uiCRC32 );
	if ( !pModule )
		return ECallResult::ModuleNotFound;

	const std::string sLegacyDir = m_sBaseDir + "/legacycompat/";
	if ( pModule->m_sFileName.empty() )
	{
		if ( !pModule->m_pRawModule || !pModule->m_uiRawModuleSize )
		{
			pModule->m_eLastResult = ECallResult::NoModuleData;
			return ECallResult::NoModuleData;
		}

		const std::string sModuleFile = sLegacyDir + "servicecall_" + std::to_string( uiCRC32 ) + ".dll";
		if ( SaveBufferToFile( pModule->m_pRawModule, pModule->m_uiRawModuleSize, sModuleFile.c_str() ) )
		{
			pModule->m_sFileName = sModuleFile;
			free( pModule->m_pRawModule );
			pModule->m_pRawModule = nullptr;
		}
	}

	if ( GetFileAttributesA( pModule->m_sFileName.c_str() ) == INVALID_FILE_ATTRIBUTES )
	{
		pModule->m_eLastResult = ECallResult::NoModuleData;
		return ECallResult::NoModuleData;
	}

	const std::string sInputFile = sLegacyDir + "servicecall_" + std::to_string( unFile ) + ".in";
	const std::string sOutputFile = sLegacyDir + "servicecall_" + std::to_string( unFile ) + ".out";
	if ( !SaveBufferToFile( pvInput, cubInput, sInputFile.c_str() ) )
	{
		pModule->m_eLastResult = ECallResult::NoModuleData;
		return ECallResult::NoModuleData;
	}

	pModule->m_eLastResult = ECallResult::Pending;
	DWORD unExitCode = 1;
	STARTUPINFOA startupInfo{};
	startupInfo.cb = sizeof( startupInfo );
	PROCESS_INFORMATION processInfo{};
	char szCommand[1024];
	snprintf( szCommand, sizeof( szCommand ), "%ssteamservice.exe /runfunc %u %u %u %u", sLegacyDir.c_str(), uiCRC32,
	          nRequest, unFile, cubOutputLimit );
	if ( CreateProcessA( nullptr, szCommand, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, m_sBaseDir.c_str(),
	                     &startupInfo, &processInfo ) )
	{
		WaitForSingleObject( processInfo.hProcess, 20000 );
		GetExitCodeProcess( processInfo.hProcess, &unExitCode );
		CloseHandle( processInfo.hProcess );
		CloseHandle( processInfo.hThread );
	}

	if ( unExitCode == 0 )
	{
		std::vector<uint8_t> vecOutput;
		if ( ReadWholeFile( sOutputFile, &vecOutput ) )
		{
			if ( vecOutput.size() > cubOutputLimit )
			{
				pModule->m_eLastResult = ECallResult::OutputTooLarge;
			}
			else
			{
				if ( !vecOutput.empty() )
				{
					*ppvOutput = malloc( vecOutput.size() );
					memcpy( *ppvOutput, vecOutput.data(), vecOutput.size() );
					*pcubOutput = static_cast<uint32_t>( vecOutput.size() );
				}
				pModule->m_eLastResult = ECallResult::OK;
			}
		}
	}

	DeleteFileA( sInputFile.c_str() );
	DeleteFileA( sOutputFile.c_str() );
	return pModule->m_eLastResult;
}

// @orig: 55 8B EC 83 EC ? 56 FF 75 ? 8B F1
void CClientModuleManagerBase::SetProtonEnvironment( uint32_t uiKey, const char *pszEnvironment )
{
	m_mapProtonEnvironments[uiKey] = pszEnvironment;
}
