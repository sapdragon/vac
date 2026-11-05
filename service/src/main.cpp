// @binary: 7ebac2a4
#include "module_manager/servicemodulemanagerbase.hpp"

#include "crypto/hash/crc32.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace
{

bool ReadWholeFile( const std::string &sName, std::vector<uint8_t> *pvecData )
{
	FILE *pFile = nullptr;
	if ( fopen_s( &pFile, sName.c_str(), "rb" ) != 0 || !pFile )
		return false;
	fseek( pFile, 0, SEEK_END );
	pvecData->resize( static_cast<size_t>( ftell( pFile ) ) );
	fseek( pFile, 0, SEEK_SET );
	const bool bRead = pvecData->empty() || fread( pvecData->data(), 1, pvecData->size(), pFile ) == pvecData->size();
	fclose( pFile );
	return bRead;
}

bool WriteWholeFile( const std::string &sName, const void *pvData, size_t cubData )
{
	FILE *pFile = nullptr;
	if ( fopen_s( &pFile, sName.c_str(), "wb" ) != 0 || !pFile )
		return false;
	const bool bWritten = fwrite( pvData, 1, cubData, pFile ) == cubData;
	fclose( pFile );
	return bWritten;
}

void ApplyDevelopmentKey( CClientModuleManagerBase &manager )
{
	char szPath[MAX_PATH];
	if ( !GetEnvironmentVariableA( "STEAMSERVICE_DEV_KEY", szPath, MAX_PATH ) )
		return;

	std::vector<uint8_t> vecKey;
	if ( ReadWholeFile( szPath, &vecKey ) )
		manager.SetDevelopmentKeys( { std::string( vecKey.begin(), vecKey.end() ) } );
}

uint32_t ComputeCrc32( const std::vector<uint8_t> &vecData )
{
	return vac::crypto::hash::Crc32_t::Of( vecData.data(), static_cast<vac::usize>( vecData.size() ) );
}

// @note / sapdragon: legacycompat/steamservice.exe isn't in what we have, only its caller. the arguments and files are
// from CallFunctionAsyncInternal_LegacyCompat, the rest of this is a guess
int RunLegacyCall( uint32_t uiCRC32, int nRequest, uint32_t unFile, uint32_t cubOutputLimit )
{
	const std::string sLegacyDir = "legacycompat/servicecall_";
	std::vector<uint8_t> vecModule;
	std::vector<uint8_t> vecInput;
	if ( !ReadWholeFile( sLegacyDir + std::to_string( uiCRC32 ) + ".dll", &vecModule ) ||
	     !ReadWholeFile( sLegacyDir + std::to_string( unFile ) + ".in", &vecInput ) )
		return 1;

	CClientModuleManagerBase manager;
	ApplyDevelopmentKey( manager );
	if ( !manager.LoadModule( uiCRC32, vecModule.data(), static_cast<uint32_t>( vecModule.size() ) ) )
		return 2;

	std::vector<uint8_t> vecOutput( cubOutputLimit < sizeof( ExceptionResponse_t ) ? sizeof( ExceptionResponse_t )
	                                                                               : cubOutputLimit );
	uint32_t cubRequired = 0;
	const ECallResult eResult = manager.CallFunction( uiCRC32, MF_HIDDEN_MODULE, nRequest, vecInput.data(),
	                                                  static_cast<uint32_t>( vecInput.size() ), vecOutput.data(),
	                                                  static_cast<uint32_t>( vecOutput.size() ), &cubRequired );
	if ( eResult != ECallResult::OK )
		return 3;
	return WriteWholeFile( sLegacyDir + std::to_string( unFile ) + ".out", vecOutput.data(), cubRequired ) ? 0 : 4;
}

int RunStandCall( int cArgs, char **ppszArgs )
{
	if ( cArgs < 6 )
		return 2;

	std::vector<uint8_t> vecModule;
	std::vector<uint8_t> vecInput;
	if ( !ReadWholeFile( ppszArgs[2], &vecModule ) || !ReadWholeFile( ppszArgs[4], &vecInput ) )
		return 2;

	const uint32_t unFlags = cArgs > 6 && !strcmp( ppszArgs[6], "--hidden" ) ? MF_HIDDEN_MODULE : 0;
	const uint32_t uiCRC32 = ComputeCrc32( vecModule );
	CClientModuleManagerBase manager;
	ApplyDevelopmentKey( manager );
	if ( !manager.LoadModule( uiCRC32, vecModule.data(), static_cast<uint32_t>( vecModule.size() ) ) )
		return 2;

	std::vector<uint8_t> vecOutput( 0x2000 );
	uint32_t cubRequired = 0;
	const ECallResult eResult = manager.CallFunction( uiCRC32, unFlags, atoi( ppszArgs[3] ), vecInput.data(),
	                                                  static_cast<uint32_t>( vecInput.size() ), vecOutput.data(),
	                                                  static_cast<uint32_t>( vecOutput.size() ), &cubRequired );
	printf( "crc=%08x result=%d output=%u\n", uiCRC32, static_cast<int>( eResult ), cubRequired );
	if ( !WriteWholeFile( ppszArgs[5], vecOutput.data(), cubRequired ) )
		return 2;
	return eResult == ECallResult::OK ? 0 : 1;
}

} // namespace

int main( int cArgs, char **ppszArgs )
{
	if ( cArgs >= 6 && !strcmp( ppszArgs[1], "/runfunc" ) )
		return RunLegacyCall( strtoul( ppszArgs[2], nullptr, 10 ), atoi( ppszArgs[3] ),
		                      strtoul( ppszArgs[4], nullptr, 10 ), strtoul( ppszArgs[5], nullptr, 10 ) );
	if ( cArgs >= 2 && !strcmp( ppszArgs[1], "--call" ) )
		return RunStandCall( cArgs, ppszArgs );

	printf( "usage: steamservice /runfunc <crc> <request> <file> <limit> | --call <dll> <request> <in> <out> "
	        "[--hidden]\n" );
	return 2;
}
