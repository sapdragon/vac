#pragma once

#include "image_loader/win32imageloader.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

// @note / sapdragon: only None, Pending and Exception are real names from valve's asserts, the rest are ours
enum class ECallResult : int
{
	None = 0,
	OK = 1,
	ModuleNotFound = 2,
	OutputTooSmall = 5,
	AllocFailed = 9,
	BadSignature = 11,
	NoModuleData = 12,
	Pending = 13,
	WorkThreadDead = 14,
	OutputTooLarge = 15,
	Exception = 16,
	TempFileFailed = 19,
	SaveFailed = 21,
	LoadFailed = 22,
	NoRunFuncLoaded = 23,
	NoRunFuncHidden = 25,
};

enum EModuleFlags : uint32_t
{
	MF_HIDDEN_MODULE = 2,
	MF_UNLOAD_AFTER_EXEC = 4,
	MF_LEGACY_COMPATIBLE = 8,
};

using PfnServiceFunction_t = int( __stdcall * )( int nRequest, const void *pvInput, uint32_t cubInput, void *pvOutput,
                                                 uint32_t *pcubOutput );

struct DynamicModule_t
{
	uint32_t m_uiCRC32;
	HMODULE m_hModule;
	CWin32ModuleLoader *m_pModule;
	PfnServiceFunction_t m_pServiceFunction;
	ECallResult m_eLastResult;
	uint32_t m_uiRawModuleSize;
	void *m_pRawModule;
	uint64_t m_ulLastUsedMicroSecs;
	std::string m_sFileName;
};

// @note / sapdragon: what a crashed module answers with, and why the output can't be under 0x58
struct ExceptionResponse_t
{
	PfnServiceFunction_t m_pServiceFunction;
	uint32_t m_unReserved;
	EXCEPTION_RECORD32 m_Record;
};
static_assert( sizeof( ExceptionResponse_t ) == 0x58 );

class CClientModuleManagerBase
{
public:
	CClientModuleManagerBase();
	virtual ~CClientModuleManagerBase();

	virtual bool LoadModule( uint32_t uiCRC32, const void *pvModule, uint32_t cubModule );
	virtual bool UnloadModule( uint32_t uiCRC32 );
	virtual ECallResult CallFunction( uint32_t uiCRC32, uint32_t unFlags, int nRequest, const void *pvInput,
	                                  uint32_t cubInput, void *pvOutput, uint32_t cubOutput, uint32_t *pcubRequired );
	void SetProtonEnvironment( uint32_t uiKey, const char *pszEnvironment );

	DynamicModule_t *FindModule( uint32_t uiCRC32 ) const;

	// @note / sapdragon: stand only. the real service has one key, and rebuilt modules can't be signed with it
	void SetDevelopmentKeys( std::vector<std::string> vecKeys ) { m_vecDevelopmentKeys = std::move( vecKeys ); }
	void SetBaseDir( std::string sBaseDir ) { m_sBaseDir = std::move( sBaseDir ); }

protected:
	bool LoadDynamicModule( DynamicModule_t *pModule, uint32_t unFlags );
	ECallResult CallFunctionAsyncInternal( uint32_t uiCRC32, uint32_t unFlags, int nRequest, const void *pvInput,
	                                       uint32_t cubInput, void **ppvOutput, uint32_t *pcubOutput );
	ECallResult CallFunctionAsyncInternal_LegacyCompat( uint32_t uiCRC32, uint32_t unFlags, int nRequest,
	                                                    uint32_t unFile, const void *pvInput, uint32_t cubInput,
	                                                    void **ppvOutput, uint32_t *pcubOutput );
	virtual uint64_t CurrentMicroSecs() const;

	static void UnloadModuleInternal( DynamicModule_t *pModule );

	std::map<uint32_t, DynamicModule_t *> m_mapModules;
	std::map<uint32_t, std::string> m_mapProtonEnvironments;
	std::vector<std::string> m_vecDevelopmentKeys;
	std::string m_sBaseDir;

private:
	bool BVerifyModule( DynamicModule_t *pModule ) const;
};
