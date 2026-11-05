#pragma once

#include <cstdint>

enum class ESignatureResult : int
{
	Valid = 0,
	Invalid = 1,
	NoValveHeader = 2,
	BadLength = 3,
	BadVersion = 4,
	NotPeImage = 6,
};

ESignatureResult VerifyValveWin32Signature( void *pvImage, uint32_t cubImage, const char *const *ppszPublicKeys,
                                            uint32_t cPublicKeys );
ESignatureResult VerifyValveSignature( void *pvImage, uint32_t cubImage );
