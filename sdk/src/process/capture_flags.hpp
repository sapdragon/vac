#pragma once

#include "core/enum.hpp"
#include "core/types.hpp"

namespace vac::process
{

enum class ECaptureFlags : u32
{
	None = 0,
	Opened = 0x000001,
	Times = 0x000002,
	Reopened = 0x000004,
	BasicInfo = 0x000008,
	PebAddress = 0x000010,
	PebRead = 0x000020,
	LdrRead = 0x000040,
	FirstEntry = 0x000080,
	Cross64 = 0x000100,
	Times64 = 0x000200,
	Entered64 = 0x000400,
	BasicInfo64 = 0x000800,
	PebAddress64 = 0x001000,
	PebRead64 = 0x002000,
	LdrRead64 = 0x004000,
	FirstEntry64 = 0x008000,
	ReopenFailed = 0x010000,
	LdrReadFailed = 0x020000,
	LdrEmpty64 = 0x040000,
	FirstEntryFailed64 = 0x080000,
	FirstEntryFailed = 0x0C0000,
	NameReadFailed = 0x100000,
	NameTooLong = 0x200000,
	EntryReadFailed = 0x400000,
};
VAC_FLAGS( ECaptureFlags )

} // namespace vac::process
