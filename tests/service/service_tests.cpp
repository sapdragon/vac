// Tests for the steamservice rebuild. Run through tests/service/run_service_tests.py, which signs the test modules.
//
//     service_tests.exe <work dir> <vac-research dir>
#include "module_manager/servicemodulemanagerasync.hpp"
#include "signature/valvesignature.hpp"
#include "image_loader/win32imageloader.hpp"

#include "crypto/hash/crc32.hpp"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

void RunMonitorTests( int *pcChecks, int *pcFailures );
int RunMonitorChild( const char *pszMappingName );

namespace fs = std::filesystem;

namespace
{

int s_cChecks = 0;
int s_cFailures = 0;
fs::path s_workDir;
fs::path s_researchDir;

#define CHECK( bCondition, ... )                                                                                       \
	do                                                                                                                 \
	{                                                                                                                  \
		++s_cChecks;                                                                                                   \
		if ( !( bCondition ) )                                                                                         \
		{                                                                                                              \
			++s_cFailures;                                                                                             \
			printf( "FAIL %s:%d %s ", __FUNCTION__, __LINE__, #bCondition );                                           \
			printf( "" __VA_ARGS__ );                                                                                  \
			printf( "\n" );                                                                                            \
		}                                                                                                              \
	} while ( 0 )

std::vector<uint8_t> ReadAll( const fs::path &path )
{
	std::ifstream file( path, std::ios::binary );
	return { std::istreambuf_iterator<char>( file ), std::istreambuf_iterator<char>() };
}

std::string ReadText( const fs::path &path )
{
	std::ifstream file( path, std::ios::binary );
	return { std::istreambuf_iterator<char>( file ), std::istreambuf_iterator<char>() };
}

uint32_t Crc32( const std::vector<uint8_t> &vecData )
{
	return vac::crypto::hash::Crc32_t::Of( vecData.data(), vecData.size() );
}

std::vector<fs::path> ResearchModules()
{
	std::vector<fs::path> vecPaths;
	for ( const auto &entry : fs::directory_iterator( s_researchDir ) )
	{
		const fs::path module = entry.path() / "module.dll";
		if ( entry.is_directory() && entry.path().filename().string().starts_with( "ptr_" ) && fs::exists( module ) )
			vecPaths.push_back( module );
	}
	return vecPaths;
}

const IMAGE_NT_HEADERS32 *NtHeaders( const std::vector<uint8_t> &vecImage )
{
	const auto *pDos = reinterpret_cast<const IMAGE_DOS_HEADER *>( vecImage.data() );
	return reinterpret_cast<const IMAGE_NT_HEADERS32 *>( vecImage.data() + pDos->e_lfanew );
}

bool BIsFreed( const void *pvAddress )
{
	MEMORY_BASIC_INFORMATION info{};
	VirtualQuery( pvAddress, &info, sizeof( info ) );
	return info.State == MEM_FREE;
}

void TestSignatures()
{
	const std::vector<fs::path> vecModules = ResearchModules();
	CHECK( vecModules.size() == 19, "found %zu", vecModules.size() );
	for ( const fs::path &path : vecModules )
	{
		std::vector<uint8_t> vecImage = ReadAll( path );
		const std::vector<uint8_t> vecSaved = vecImage;
		CHECK( VerifyValveSignature( vecImage.data(), static_cast<uint32_t>( vecImage.size() ) ) ==
		           ESignatureResult::Valid,
		       "%s", path.parent_path().filename().string().c_str() );
		CHECK( vecImage == vecSaved, "verify must restore the image" );

		const auto *pHeaders = NtHeaders( vecImage );
		const uint32_t ibOptional =
		    static_cast<uint32_t>( reinterpret_cast<const uint8_t *>( &pHeaders->OptionalHeader ) - vecImage.data() );

		std::vector<uint8_t> vecCopy = vecSaved;
		vecCopy[vecCopy.size() / 2] ^= 1;
		CHECK( VerifyValveSignature( vecCopy.data(), static_cast<uint32_t>( vecCopy.size() ) ) ==
		       ESignatureResult::Invalid );

		vecCopy = vecSaved;
		vecCopy[0x50] ^= 1;
		CHECK( VerifyValveSignature( vecCopy.data(), static_cast<uint32_t>( vecCopy.size() ) ) ==
		       ESignatureResult::Invalid );

		vecCopy = vecSaved;
		vecCopy[ibOptional + 64] ^= 1;
		CHECK( VerifyValveSignature( vecCopy.data(), static_cast<uint32_t>( vecCopy.size() ) ) ==
		           ESignatureResult::Valid,
		       "checksum stays out of the hash" );

		vecCopy = vecSaved;
		vecCopy[ibOptional + 128] ^= 1;
		CHECK( VerifyValveSignature( vecCopy.data(), static_cast<uint32_t>( vecCopy.size() ) ) ==
		           ESignatureResult::Valid,
		       "security directory stays out of the hash" );

		vecCopy = vecSaved;
		vecCopy[0x40] ^= 1;
		CHECK( VerifyValveSignature( vecCopy.data(), static_cast<uint32_t>( vecCopy.size() ) ) ==
		       ESignatureResult::NoValveHeader );

		vecCopy = vecSaved;
		vecCopy[0x44] = 2;
		CHECK( VerifyValveSignature( vecCopy.data(), static_cast<uint32_t>( vecCopy.size() ) ) ==
		       ESignatureResult::BadVersion );

		vecCopy = vecSaved;
		const uint32_t cubTooLarge = static_cast<uint32_t>( vecCopy.size() ) + 1;
		memcpy( &vecCopy[0x48], &cubTooLarge, sizeof( cubTooLarge ) );
		CHECK( VerifyValveSignature( vecCopy.data(), static_cast<uint32_t>( vecCopy.size() ) ) ==
		       ESignatureResult::BadLength );

		vecCopy = vecSaved;
		CHECK( VerifyValveSignature( vecCopy.data(), 0x1FF ) == ESignatureResult::NotPeImage );
		vecCopy[0] = 0;
		CHECK( VerifyValveSignature( vecCopy.data(), static_cast<uint32_t>( vecCopy.size() ) ) ==
		       ESignatureResult::NotPeImage );
	}

	std::vector<uint8_t> vecSigned = ReadAll( s_workDir / "test_module.signed.dll" );
	CHECK( VerifyValveSignature( vecSigned.data(), static_cast<uint32_t>( vecSigned.size() ) ) ==
	           ESignatureResult::Invalid,
	       "a test signature must fail the real key" );
	const std::string sKey = ReadText( s_workDir / "devkey.hex" );
	const char *const rgpszKeys[] = { "", "not hex", sKey.c_str() };
	CHECK( VerifyValveWin32Signature( vecSigned.data(), static_cast<uint32_t>( vecSigned.size() ), rgpszKeys, 3 ) ==
	           ESignatureResult::Valid,
	       "bad key slots get skipped" );
	CHECK( VerifyValveWin32Signature( vecSigned.data(), static_cast<uint32_t>( vecSigned.size() ), rgpszKeys, 2 ) ==
	       ESignatureResult::Invalid );
}

void TestLoaderMapsOriginals()
{
	for ( const fs::path &path : ResearchModules() )
	{
		const std::vector<uint8_t> vecImage = ReadAll( path );
		const auto *pHeaders = NtHeaders( vecImage );
		CHECK( pHeaders->OptionalHeader.AddressOfEntryPoint == 0, "%s has an entry point",
		       path.parent_path().filename().string().c_str() );
		if ( pHeaders->OptionalHeader.AddressOfEntryPoint )
			continue;

		CWin32ModuleLoader *pImage = LoadModuleHiddenInternal( vecImage.data(), nullptr, true );
		CHECK( pImage != nullptr, "%s", path.parent_path().filename().string().c_str() );
		if ( !pImage )
			continue;

		CHECK( !pImage->m_bModuleLoaded, "no entry point means not marked as loaded" );
		CHECK( GetProcAddressHidden( pImage, "_runfunc@20" ) != nullptr );
		CHECK( GetProcAddressHidden( pImage, "_RUNFUNC@20" ) != nullptr, "valve compares with _stricmp" );
		CHECK( GetProcAddressHidden( pImage, "nothing" ) == nullptr );

		const auto *pSection = IMAGE_FIRST_SECTION( pHeaders );
		auto *pubBase = static_cast<const uint8_t *>( pImage->m_pBaseAddress );
		for ( WORD iSection = 0; iSection < pHeaders->FileHeader.NumberOfSections; ++iSection, ++pSection )
		{
			if ( pSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE || !pSection->SizeOfRawData )
				continue;

			MEMORY_BASIC_INFORMATION info{};
			VirtualQuery( pubBase + pSection->VirtualAddress, &info, sizeof( info ) );
			const bool bExecute = pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE;
			const bool bWrite = pSection->Characteristics & IMAGE_SCN_MEM_WRITE;
			const DWORD unExpected = bExecute ? ( bWrite ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ )
			                                  : ( bWrite ? PAGE_READWRITE : PAGE_READONLY );
			CHECK( info.Protect == unExpected, "%.8s protect %lx, expected %lx", pSection->Name, info.Protect,
			       unExpected );
		}

		const void *pvBase = pImage->m_pBaseAddress;
		UnloadModuleHiddenInternal( pImage );
		CHECK( BIsFreed( pvBase ) );
	}
}

void TestLoaderRelocations()
{
	const std::vector<uint8_t> vecImage = ReadAll( s_workDir / "test_module.signed.dll" );
	CWin32ModuleLoader *pFirst = LoadModuleHiddenInternal( vecImage.data(), nullptr, true );
	CWin32ModuleLoader *pSecond = LoadModuleHiddenInternal( vecImage.data(), nullptr, true );
	CHECK( pFirst && pSecond );
	if ( !pFirst || !pSecond )
		return;

	CHECK( pFirst->m_pBaseAddress != pSecond->m_pBaseAddress, "same base twice" );
	for ( CWin32ModuleLoader *pImage : { pFirst, pSecond } )
	{
		const auto pfnRun = reinterpret_cast<PfnServiceFunction_t>( GetProcAddressHidden( pImage, "_runfunc@20" ) );
		CHECK( pfnRun != nullptr );
		uint32_t rgunOutput[2]{};
		uint32_t cubOutput = sizeof( rgunOutput );
		const uint8_t ubInput = 0x5A;
		CHECK( pfnRun( 0, &ubInput, 1, rgunOutput, &cubOutput ) == 1 );
		CHECK( rgunOutput[0] == 0x1234, "relocated pointer read %x", rgunOutput[0] );
		CHECK( rgunOutput[1] == 0x5A );
		CHECK( pImage->m_pNTHeaders->OptionalHeader.ImageBase ==
		       reinterpret_cast<uintptr_t>( pImage->m_pBaseAddress ) );
	}
	UnloadModuleHiddenInternal( pSecond );
	UnloadModuleHiddenInternal( pFirst );

	std::vector<uint8_t> vecBad = vecImage;
	vecBad[0] = 0;
	CHECK( LoadModuleHiddenInternal( vecBad.data(), nullptr, true ) == nullptr );
	vecBad = vecImage;
	vecBad[reinterpret_cast<const IMAGE_DOS_HEADER *>( vecBad.data() )->e_lfanew] = 0;
	CHECK( LoadModuleHiddenInternal( vecBad.data(), nullptr, true ) == nullptr );
}

void TestLoaderEntryPoint()
{
	std::vector<uint8_t> vecImage = ReadAll( s_workDir / "test_module_entry.signed.dll" );
	CWin32ModuleLoader *pImage = LoadModuleHiddenInternal( vecImage.data(), nullptr, true );
	CHECK( pImage != nullptr );
	if ( !pImage )
		return;

	CHECK( pImage->m_bModuleLoaded, "a real entry point marks it loaded" );
	const auto pfnAttachCount =
	    reinterpret_cast<LONG( __stdcall * )()>( GetProcAddressHidden( pImage, "_AttachCount@0" ) );
	CHECK( pfnAttachCount && pfnAttachCount() == 1, "entry runs once with DLL_PROCESS_ATTACH" );
	const auto pfnImportProbe =
	    reinterpret_cast<DWORD( __stdcall * )()>( GetProcAddressHidden( pImage, "_ImportProbe@0" ) );
	CHECK( pfnImportProbe && pfnImportProbe() == GetCurrentProcessId(), "imports resolved" );

	const uint8_t *pubBase = static_cast<const uint8_t *>( pImage->m_pBaseAddress );
	const uint32_t ibFailingEntry = static_cast<uint32_t>(
	    static_cast<const uint8_t *>( GetProcAddressHidden( pImage, "_FailingEntry@12" ) ) - pubBase );
	CHECK( ibFailingEntry != 0 );
	const void *pvBase = pImage->m_pBaseAddress;
	UnloadModuleHiddenInternal( pImage );
	CHECK( BIsFreed( pvBase ) );

	const auto *pHeaders = NtHeaders( vecImage );
	const uint32_t ibEntry = static_cast<uint32_t>(
	    reinterpret_cast<const uint8_t *>( &pHeaders->OptionalHeader.AddressOfEntryPoint ) - vecImage.data() );
	memcpy( &vecImage[ibEntry], &ibFailingEntry, sizeof( ibFailingEntry ) );
	CHECK( LoadModuleHiddenInternal( vecImage.data(), nullptr, true ) == nullptr,
	       "an entry point that fails unloads the image" );

	const std::vector<uint8_t> vecNoEntryCall = ReadAll( s_workDir / "test_module_entry.signed.dll" );
	pImage = LoadModuleHiddenInternal( vecNoEntryCall.data(), nullptr, false );
	CHECK( pImage && !pImage->m_bModuleLoaded, "imports and entry point are skipped without the flag" );
	if ( pImage )
		UnloadModuleHiddenInternal( pImage );
}

void TestManager()
{
	const std::vector<uint8_t> vecModule = ReadAll( s_workDir / "test_module.signed.dll" );
	const uint32_t uiCRC32 = Crc32( vecModule );
	const std::string sKey = ReadText( s_workDir / "devkey.hex" );
	const uint8_t ubInput = 7;
	uint8_t rgubOutput[0x100]{};
	uint32_t cubRequired = 0;

	{
		CClientModuleManagerBase manager;
		manager.SetDevelopmentKeys( { sKey } );
		CHECK( !manager.LoadModule( 0, vecModule.data(), static_cast<uint32_t>( vecModule.size() ) ) );
		CHECK( !manager.LoadModule( uiCRC32, nullptr, 1 ) );
		CHECK( !manager.LoadModule( uiCRC32, vecModule.data(), 0 ) );
		CHECK( !manager.LoadModule( uiCRC32, vecModule.data(), 0x1000000 ) );
		CHECK( !manager.LoadModule( uiCRC32 + 1, vecModule.data(), static_cast<uint32_t>( vecModule.size() ) ),
		       "the crc is checked" );
		CHECK( manager.CallFunction( uiCRC32, MF_HIDDEN_MODULE, 0, &ubInput, 1, rgubOutput, sizeof( rgubOutput ),
		                             &cubRequired ) == ECallResult::ModuleNotFound );

		CHECK( manager.LoadModule( uiCRC32, vecModule.data(), static_cast<uint32_t>( vecModule.size() ) ) );
		CHECK( manager.LoadModule( uiCRC32, vecModule.data(), static_cast<uint32_t>( vecModule.size() ) ),
		       "loading twice is fine" );
		CHECK( manager.CallFunction( uiCRC32, MF_HIDDEN_MODULE, 0, &ubInput, 1, rgubOutput, 0x57, &cubRequired ) ==
		       ECallResult::OutputTooSmall );

		CHECK( manager.CallFunction( uiCRC32, MF_HIDDEN_MODULE, 0, &ubInput, 1, rgubOutput, sizeof( rgubOutput ),
		                             &cubRequired ) == ECallResult::OK );
		CHECK( cubRequired == 8 );
		CHECK( *reinterpret_cast<uint32_t *>( rgubOutput ) == 0x1234 );
		CHECK( manager.FindModule( uiCRC32 )->m_pModule != nullptr );
		CHECK( manager.FindModule( uiCRC32 )->m_pRawModule == nullptr, "the raw image is freed after load" );

		CHECK( manager.CallFunction( uiCRC32, MF_HIDDEN_MODULE, 3, &ubInput, 1, rgubOutput, sizeof( rgubOutput ),
		                             &cubRequired ) == static_cast<ECallResult>( 77 ),
		       "worker results pass through" );

		CHECK( manager.CallFunction( uiCRC32, MF_HIDDEN_MODULE, 1, &ubInput, 1, rgubOutput, sizeof( rgubOutput ),
		                             &cubRequired ) == ECallResult::Exception );
		CHECK( cubRequired == sizeof( ExceptionResponse_t ) );
		const auto *pResponse = reinterpret_cast<const ExceptionResponse_t *>( rgubOutput );
		CHECK( pResponse->m_pServiceFunction == manager.FindModule( uiCRC32 )->m_pServiceFunction );
		CHECK( pResponse->m_unReserved == 0 );
		CHECK( pResponse->m_Record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION );

		const void *pvBase = manager.FindModule( uiCRC32 )->m_pModule->m_pBaseAddress;
		CHECK( manager.CallFunction( uiCRC32, MF_HIDDEN_MODULE | MF_UNLOAD_AFTER_EXEC, 0, &ubInput, 1, rgubOutput,
		                             sizeof( rgubOutput ), &cubRequired ) == ECallResult::OK );
		CHECK( manager.FindModule( uiCRC32 ) == nullptr, "unload after exec" );
		CHECK( BIsFreed( pvBase ) );
		CHECK( !manager.UnloadModule( uiCRC32 ) );
	}

	{
		CClientModuleManagerBase manager;
		manager.SetDevelopmentKeys( { sKey } );
		CHECK( manager.LoadModule( uiCRC32, vecModule.data(), static_cast<uint32_t>( vecModule.size() ) ) );
		CHECK( manager.CallFunction( uiCRC32, 0, 0, &ubInput, 1, rgubOutput, sizeof( rgubOutput ), &cubRequired ) ==
		           ECallResult::OK,
		       "loaded through a temp file" );
		const std::string sTempFile = manager.FindModule( uiCRC32 )->m_sFileName;
		CHECK( manager.FindModule( uiCRC32 )->m_hModule != nullptr );
		CHECK( fs::exists( sTempFile ) );
		CHECK( manager.UnloadModule( uiCRC32 ) );
		CHECK( !fs::exists( sTempFile ), "unload deletes the temp file" );
	}

	{
		CClientModuleManagerBase manager;
		CHECK( manager.LoadModule( uiCRC32, vecModule.data(), static_cast<uint32_t>( vecModule.size() ) ) );
		CHECK( manager.CallFunction( uiCRC32, MF_HIDDEN_MODULE, 0, &ubInput, 1, rgubOutput, sizeof( rgubOutput ),
		                             &cubRequired ) == ECallResult::BadSignature,
		       "a real manager refuses our signature" );
		CHECK( manager.FindModule( uiCRC32 )->m_pRawModule == nullptr, "a bad signature drops the image" );
		CHECK( manager.CallFunction( uiCRC32, MF_HIDDEN_MODULE, 0, &ubInput, 1, rgubOutput, sizeof( rgubOutput ),
		                             &cubRequired ) == ECallResult::NoModuleData );
	}

	{
		const std::vector<uint8_t> vecNoRunFunc = ReadAll( s_workDir / "test_module_entry.signed.dll" );
		const uint32_t uiNoRunFunc = Crc32( vecNoRunFunc );
		CClientModuleManagerBase manager;
		manager.SetDevelopmentKeys( { sKey } );
		CHECK( manager.LoadModule( uiNoRunFunc, vecNoRunFunc.data(), static_cast<uint32_t>( vecNoRunFunc.size() ) ) );
		CHECK( manager.CallFunction( uiNoRunFunc, MF_HIDDEN_MODULE, 0, &ubInput, 1, rgubOutput, sizeof( rgubOutput ),
		                             &cubRequired ) == ECallResult::NoRunFuncHidden );
		CHECK( manager.UnloadModule( uiNoRunFunc ) );
		CHECK( manager.LoadModule( uiNoRunFunc, vecNoRunFunc.data(), static_cast<uint32_t>( vecNoRunFunc.size() ) ) );
		CHECK( manager.CallFunction( uiNoRunFunc, 0, 0, &ubInput, 1, rgubOutput, sizeof( rgubOutput ), &cubRequired ) ==
		       ECallResult::NoRunFuncLoaded );
	}
}

class CFakeClockManager : public CClientModuleManagerAsync
{
public:
	uint64_t m_ulNow = 1000000;

protected:
	uint64_t CurrentMicroSecs() const override { return m_ulNow; }
};

ECallResult WaitForResponse( CClientModuleManagerAsync &manager, void *pvBuffer, uint32_t cubBuffer,
                             uint32_t *pcubStatus, uint32_t unFile, uint32_t unCaller )
{
	for ( int iTry = 0; iTry < 5000; ++iTry )
	{
		const ECallResult eResult = manager.PollResponseAsync( pvBuffer, cubBuffer, pcubStatus, unFile, unCaller );
		if ( eResult != ECallResult::None )
			return eResult;
		Sleep( 2 );
	}
	return ECallResult::None;
}

void TestAsync()
{
	const std::vector<uint8_t> vecModule = ReadAll( s_workDir / "test_module.signed.dll" );
	const uint32_t uiCRC32 = Crc32( vecModule );
	const std::string sKey = ReadText( s_workDir / "devkey.hex" );
	const uint8_t ubInput = 9;
	uint8_t rgubBuffer[0x200]{};
	uint32_t cubStatus = 0;

	CFakeClockManager manager;
	manager.SetDevelopmentKeys( { sKey } );
	CHECK( manager.LoadModule( uiCRC32, vecModule.data(), static_cast<uint32_t>( vecModule.size() ) ) );
	CHECK( manager.PollResponseAsync( rgubBuffer, sizeof( rgubBuffer ), &cubStatus, 1, 1 ) == ECallResult::None );

	CHECK( manager.CallFunctionAsync( uiCRC32, MF_HIDDEN_MODULE, 11, 0, 0, 100, &ubInput, 1, 0x100 ) ==
	       ECallResult::OK );
	CHECK( manager.CallFunctionAsync( uiCRC32, MF_HIDDEN_MODULE, 22, 0, 0, 200, &ubInput, 1, 0x100 ) ==
	       ECallResult::OK );
	CHECK( WaitForResponse( manager, rgubBuffer, sizeof( rgubBuffer ), &cubStatus, 200, 22 ) == ECallResult::OK,
	       "the second call first, the first one waits in the list" );
	CHECK( cubStatus == 8 );
	CHECK( WaitForResponse( manager, rgubBuffer, sizeof( rgubBuffer ), &cubStatus, 100, 11 ) == ECallResult::OK );
	CHECK( *reinterpret_cast<uint32_t *>( rgubBuffer ) == 0x1234 );

	CHECK( manager.CallFunctionAsync( uiCRC32, MF_HIDDEN_MODULE, 1, 0, 1, 300, &ubInput, 1, 0x100 ) ==
	       ECallResult::OK );
	CHECK( WaitForResponse( manager, rgubBuffer, sizeof( rgubBuffer ), &cubStatus, 300, 1 ) == ECallResult::Exception );
	CHECK( cubStatus == sizeof( ExceptionResponse_t ) );
	CHECK( reinterpret_cast<const ExceptionResponse_t *>( rgubBuffer )->m_Record.ExceptionCode ==
	       EXCEPTION_ACCESS_VIOLATION );

	CHECK( manager.CallFunctionAsync( uiCRC32, MF_HIDDEN_MODULE, 2, 0, 2, 400, &ubInput, 1, 0x100 ) ==
	       ECallResult::OK );
	CHECK( WaitForResponse( manager, rgubBuffer, sizeof( rgubBuffer ), &cubStatus, 400, 2 ) ==
	           ECallResult::OutputTooLarge,
	       "the worker asks past the limit" );

	CHECK( manager.CallFunctionAsync( uiCRC32, MF_HIDDEN_MODULE, 3, 0, 0, 500, &ubInput, 1, 0x100 ) ==
	       ECallResult::OK );
	CHECK( WaitForResponse( manager, rgubBuffer, 4, &cubStatus, 500, 3 ) == ECallResult::OutputTooSmall,
	       "the poll buffer is too small" );

	CHECK( manager.CallFunctionAsync( uiCRC32, MF_HIDDEN_MODULE, 1, 0, 1, 600, &ubInput, 1, 0x100 ) ==
	       ECallResult::OK );
	CHECK( WaitForResponse( manager, rgubBuffer, 4, &cubStatus, 600, 1 ) == ECallResult::OutputTooLarge,
	       "a crash report that does not fit" );

	CHECK( manager.FindModule( uiCRC32 ) != nullptr );
	manager.m_ulNow += 1800ull * 1000000;
	manager.PollResponseAsync( rgubBuffer, sizeof( rgubBuffer ), &cubStatus, 1, 1 );
	CHECK( manager.FindModule( uiCRC32 ) != nullptr, "1800 seconds is not over the limit yet" );
	manager.m_ulNow += 1000000;
	manager.PollResponseAsync( rgubBuffer, sizeof( rgubBuffer ), &cubStatus, 1, 1 );
	CHECK( manager.FindModule( uiCRC32 ) == nullptr, "idle modules get unloaded" );
}

void TestLegacyCompat( const fs::path &serviceExe )
{
	const fs::path baseDir = s_workDir / "legacy_base";
	fs::remove_all( baseDir );
	fs::create_directories( baseDir / "legacycompat" );
	const std::vector<uint8_t> vecModule = ReadAll( s_workDir / "test_module.signed.dll" );
	const uint32_t uiCRC32 = Crc32( vecModule );
	const uint8_t ubInput = 4;
	uint8_t rgubBuffer[0x200]{};
	uint32_t cubStatus = 0;

	{
		CClientModuleManagerAsync manager;
		manager.SetBaseDir( baseDir.string() );
		CHECK( manager.LoadModule( uiCRC32, vecModule.data(), static_cast<uint32_t>( vecModule.size() ) ) );
		CHECK( manager.CallFunctionAsync( uiCRC32, MF_LEGACY_COMPATIBLE, 5, 0, 0, 700, &ubInput, 1, 0x100 ) ==
		       ECallResult::OK );
		CHECK( WaitForResponse( manager, rgubBuffer, sizeof( rgubBuffer ), &cubStatus, 700, 5 ) == ECallResult::Pending,
		       "no helper exe stays pending" );
		CHECK( !fs::exists( baseDir / "legacycompat" / "servicecall_700.in" ), "the input file is removed" );
		CHECK( fs::exists( baseDir / "legacycompat" / ( "servicecall_" + std::to_string( uiCRC32 ) + ".dll" ) ) );
		manager.Shutdown();
	}

	fs::copy_file( serviceExe, baseDir / "legacycompat" / "steamservice.exe" );
	SetEnvironmentVariableA( "STEAMSERVICE_DEV_KEY", ( s_workDir / "devkey.hex" ).string().c_str() );
	{
		CClientModuleManagerAsync manager;
		manager.SetBaseDir( baseDir.string() );
		CHECK( manager.LoadModule( uiCRC32, vecModule.data(), static_cast<uint32_t>( vecModule.size() ) ) );
		CHECK( manager.CallFunctionAsync( uiCRC32, MF_LEGACY_COMPATIBLE, 0, 0, 0, 701, &ubInput, 1, 0x100 ) ==
		       ECallResult::OK );
		CHECK( WaitForResponse( manager, rgubBuffer, sizeof( rgubBuffer ), &cubStatus, 701, 0 ) == ECallResult::OK );
		CHECK( cubStatus == 8, "got %u", cubStatus );
		CHECK( *reinterpret_cast<uint32_t *>( rgubBuffer ) == 0x1234 );
		CHECK( rgubBuffer[4] == ubInput, "the input went through the file" );
		CHECK( !fs::exists( baseDir / "legacycompat" / "servicecall_701.in" ) );
		CHECK( !fs::exists( baseDir / "legacycompat" / "servicecall_701.out" ) );

		CHECK( manager.CallFunctionAsync( uiCRC32, MF_LEGACY_COMPATIBLE, 0, 0, 1, 702, &ubInput, 1, 0x100 ) ==
		       ECallResult::OK );
		CHECK( WaitForResponse( manager, rgubBuffer, sizeof( rgubBuffer ), &cubStatus, 702, 0 ) == ECallResult::Pending,
		       "a crash in the helper leaves it pending" );

		manager.Shutdown();
		CHECK( manager.UnloadModule( uiCRC32 ) );
		CHECK( !fs::exists( baseDir / "legacycompat" / ( "servicecall_" + std::to_string( uiCRC32 ) + ".dll" ) ),
		       "unload removes the dll" );
	}
	SetEnvironmentVariableA( "STEAMSERVICE_DEV_KEY", nullptr );
}

// @note / sapdragon: only modules that are safe to replay. target_handles does raw syscalls, so it never runs here
void TestRealModulesThroughManager()
{
	struct Case_t
	{
		const char *m_pszOriginalFolder;
		const char *m_pszRebuild;
		int m_nMode;
	};
	const Case_t rgCases[] = {
	    { "ptr_0x0D2A9410_crc_f418b1dc_SomeCpuId_info", "cpuid.signed.dll", 4 },
	    { "ptr_0x00A69D50_crc_40e4df95_GetDeviceInfo", "devices.signed.dll", 4 },
	};
	const std::string sKey = ReadText( s_workDir / "devkey.hex" );
	for ( const Case_t &testCase : rgCases )
	{
		const fs::path folder = s_researchDir / testCase.m_pszOriginalFolder;
		const std::vector<uint8_t> vecPacket = ReadAll( folder / "inputVacPacket_ScanId_4.bin" );
		const std::vector<uint8_t> vecOriginal = ReadAll( folder / "module.dll" );
		const std::vector<uint8_t> vecRebuild = ReadAll( s_workDir / testCase.m_pszRebuild );
		const uint32_t uiOriginal = Crc32( vecOriginal );
		const uint32_t uiRebuild = Crc32( vecRebuild );

		std::vector<uint8_t> vecOutputOriginal( 0x2000 );
		std::vector<uint8_t> vecOutputRebuild( 0x2000 );
		uint32_t cubOriginal = 0;
		uint32_t cubRebuild = 0;

		CClientModuleManagerBase managerOriginal;
		CHECK(
		    managerOriginal.LoadModule( uiOriginal, vecOriginal.data(), static_cast<uint32_t>( vecOriginal.size() ) ) );
		std::vector<uint8_t> vecInput = vecPacket;
		const ECallResult eOriginal = managerOriginal.CallFunction(
		    uiOriginal, MF_HIDDEN_MODULE, testCase.m_nMode, vecInput.data(), static_cast<uint32_t>( vecInput.size() ),
		    vecOutputOriginal.data(), static_cast<uint32_t>( vecOutputOriginal.size() ), &cubOriginal );

		CClientModuleManagerBase managerRebuild;
		managerRebuild.SetDevelopmentKeys( { sKey } );
		CHECK( managerRebuild.LoadModule( uiRebuild, vecRebuild.data(), static_cast<uint32_t>( vecRebuild.size() ) ) );
		vecInput = vecPacket;
		const ECallResult eRebuild = managerRebuild.CallFunction(
		    uiRebuild, MF_HIDDEN_MODULE, testCase.m_nMode, vecInput.data(), static_cast<uint32_t>( vecInput.size() ),
		    vecOutputRebuild.data(), static_cast<uint32_t>( vecOutputRebuild.size() ), &cubRebuild );

		printf( "module %s: original result=%d size=%u, rebuild result=%d size=%u\n", testCase.m_pszRebuild,
		        static_cast<int>( eOriginal ), cubOriginal, static_cast<int>( eRebuild ), cubRebuild );
		CHECK( eOriginal != ECallResult::Exception && eOriginal != ECallResult::BadSignature &&
		       eOriginal != ECallResult::LoadFailed );
		CHECK( eOriginal == eRebuild, "%d vs %d", static_cast<int>( eOriginal ), static_cast<int>( eRebuild ) );
		CHECK( cubOriginal == cubRebuild, "%u vs %u", cubOriginal, cubRebuild );
	}
}

} // namespace

int main( int cArgs, char **ppszArgs )
{
	if ( cArgs == 3 && !strcmp( ppszArgs[1], "--monitor-child" ) )
		return RunMonitorChild( ppszArgs[2] );

	if ( cArgs < 4 )
	{
		printf( "usage: service_tests <work dir> <vac-research dir> <steamservice.exe>\n" );
		return 2;
	}
	s_workDir = ppszArgs[1];
	s_researchDir = ppszArgs[2];

	TestSignatures();
	TestLoaderMapsOriginals();
	TestLoaderRelocations();
	TestLoaderEntryPoint();
	TestManager();
	TestAsync();
	TestLegacyCompat( ppszArgs[3] );
	TestRealModulesThroughManager();
	RunMonitorTests( &s_cChecks, &s_cFailures );

	printf( "checks=%d failures=%d\n", s_cChecks, s_cFailures );
	return s_cFailures ? 1 : 0;
}
