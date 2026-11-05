// @binary: 40e4df95
#include "internal/types.hpp"

namespace vac::workers::devices
{

// @orig: 51 51 53 55 56 57 8B FA
int ParseHex( const char *pszText, u32 cDigits, u32 *punValue ) noexcept
{
	u32 unValue = 0;
	for ( u32 iDigit = 0; iDigit < cDigits; ++iDigit )
	{
		const char chText = pszText[iDigit];
		if ( chText == 0 )
			return 2;

		char chLower = static_cast<char>( chText + 32 );
		if ( static_cast<unsigned>( chText - 'A' ) > 25u )
			chLower = chText;

		u32 unNibble;
		if ( static_cast<unsigned>( chLower - '0' ) <= 9u )
		{
			unNibble = static_cast<u32>( chLower - '0' );
		}
		else
		{
			if ( static_cast<unsigned>( chLower - 'a' ) > 5u )
				return 3;
			unNibble = static_cast<u32>( chLower - 'a' + 10 );
		}

		unValue += unNibble << ( 4 * ( cDigits - iDigit ) - 4 );
	}

	*punValue = unValue;
	return 0;
}

// @orig: 53 56 57 8B FA 8B C1
char *FindString( char *pszHaystack, const char *pszNeedle ) noexcept
{
	char *pszStart = pszHaystack;
	for ( ;; )
	{
		char *pszChar = pszStart;
		const char *pszWanted = pszNeedle;
		while ( *pszWanted && *pszChar == *pszWanted )
		{
			++pszChar;
			++pszWanted;
		}
		if ( !*pszWanted )
			return pszStart;
		if ( !*pszStart )
			return nullptr;
		++pszStart;
	}
}

} // namespace vac::workers::devices
