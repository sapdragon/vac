#pragma once

#include "core/types.hpp"

#include <winerror.h>

namespace vac
{

// @note / sapdragon: same table in every module, so valve has one shared enum. a field can also hold a raw last error
enum class EScanStatus : u32
{
	Ok = 0,
	NoFile = ERROR_FILE_NOT_FOUND,
	BadHandleValue = ERROR_INVALID_HANDLE,
	NotEnoughMemory = ERROR_NOT_ENOUGH_MEMORY,
	OpenFailed = 10,
	SeekFailed = 12,
	ReadFailed = 13,
	NoTargetHandle = 13,
	HeapAllocFailed = ERROR_OUTOFMEMORY,
	BadImage = 20,
	BadOptionalHeader = 21,
	CpuidUnsupported = 30,
	NoSyscallNumber = 44,
	TokenFailed = 50,
	ProcessReadFailed = 60,
	ProcessReopenFailed = 61,
	NoThreads = 62,
	TooManyModules = 63,
	NoPeb = 66,
	ProcessOpenFailed = 67,
	BasicInfoFailed = 68,
	PebReadFailed = 69,
	BootstrapFailed = 78,
	UnknownStub = 79,
	NoSection = 82,
	ScanDone = 85,
	AllocFailed = ERROR_INVALID_PARAMETER,
	NoDebugDirectory = 94,
	NoDebugSection = 96,
	OutOfMemory = 97,
	TooManyDevices = ERROR_BUFFER_OVERFLOW,
	DuplicateHandle = ERROR_INVALID_TARGET_HANDLE,
	TooManyRows = ERROR_INSUFFICIENT_BUFFER,
	RecordOverflow = ERROR_MORE_DATA,
	HandleBufferLimit = ERROR_TOO_MANY_DESCRIPTORS,
	Timeout = ERROR_TIMEOUT,
	NoImageName = ERROR_FUNCTION_NOT_CALLED,
	InternalError = 0xFFFFFFFF,
};

} // namespace vac
