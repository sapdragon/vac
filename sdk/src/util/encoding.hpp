// @binary: 42878040
#pragma once

#include "bootstrap/imports.hpp"
#include "core/types.hpp"

namespace vac::util::encoding
{

inline void WideToUtf8( const SystemImports_t *pImports, const wchar_t *pwszIn, char *pszOut, u32 cubOut ) noexcept
{
	if ( !cubOut )
		return;
	pszOut[0] = 0;
	if ( !pImports || !pImports->WideCharToMultiByte || !pwszIn || !pwszIn[0] )
		return;
	pImports->WideCharToMultiByte( CP_UTF8, 0, pwszIn, -1, pszOut, static_cast<int>( cubOut ), nullptr, nullptr );
	pszOut[cubOut - 1] = 0;
}

inline void Utf8ToWide( const SystemImports_t *pImports, const char *pszIn, wchar_t *pwszOut, u32 cOut ) noexcept
{
	if ( !cOut )
		return;
	pwszOut[0] = 0;
	if ( !pImports || !pImports->MultiByteToWideChar || !pszIn || !pszIn[0] )
		return;
	pImports->MultiByteToWideChar( CP_UTF8, 0, pszIn, -1, pwszOut, static_cast<int>( cOut ) );
	pwszOut[cOut - 1] = 0;
}

// @note / sapdragon: the converter the originals actually have: only a failed conversion touches the last byte
// @orig: A1 ? ? ? ? 53 56 57
inline int WideToUtf8Bounded( const SystemImports_t *pImports, const wchar_t *pwszIn, char *pszOut,
                              int cubOut ) noexcept
{
	const int nResult = pImports->WideCharToMultiByte( CP_UTF8, 0, pwszIn, -1, pszOut, cubOut, nullptr, nullptr );
	if ( nResult == 0 )
		pszOut[cubOut - 1] = 0;
	return nResult;
}

} // namespace vac::util::encoding
