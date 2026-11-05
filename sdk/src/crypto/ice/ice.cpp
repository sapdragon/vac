// @binary: 9b85c913
#include "crypto/ice/ice.hpp"

namespace vac::crypto::ice
{

void EncryptBuffer( const IceKey_t &key, const u8 *pubIn, usize cubData, u8 *pubOut ) noexcept
{
	const usize cBlocks = cubData / k_cubBlock;
	for ( usize iBlock = 0; iBlock < cBlocks; ++iBlock )
		EncryptBlock( key, pubIn + iBlock * k_cubBlock, pubOut + iBlock * k_cubBlock );
}

void DecryptBuffer( const IceKey_t &key, const u8 *pubIn, usize cubData, u8 *pubOut ) noexcept
{
	const usize cBlocks = cubData / k_cubBlock;
	for ( usize iBlock = 0; iBlock < cBlocks; ++iBlock )
		DecryptBlock( key, pubIn + iBlock * k_cubBlock, pubOut + iBlock * k_cubBlock );
}

void EncryptBuffer( const u8 ( &rgubKey )[k_cubKey], const u8 *pubIn, usize cubData, u8 *pubOut ) noexcept
{
	EncryptBuffer( IceKey_t{ rgubKey }, pubIn, cubData, pubOut );
}

void DecryptBuffer( const u8 ( &rgubKey )[k_cubKey], const u8 *pubIn, usize cubData, u8 *pubOut ) noexcept
{
	DecryptBuffer( IceKey_t{ rgubKey }, pubIn, cubData, pubOut );
}

// @orig: 55 8B EC 83 EC ? 53 56 57 8B F9
void EncryptBuffer( const u8 *pubKey, const u8 *pubIn, usize cubData, u8 *pubOut ) noexcept
{
	u8 rgubKey[k_cubKey]{};
	for ( usize ib = 0; ib < k_cubKey; ++ib )
		rgubKey[ib] = pubKey[ib];
	EncryptBuffer( IceKey_t{ rgubKey }, pubIn, cubData, pubOut );
}

// @orig: 55 8B EC 83 EC ? 53 56 57 8B D9
void DecryptBuffer( const u8 *pubKey, const u8 *pubIn, usize cubData, u8 *pubOut ) noexcept
{
	u8 rgubKey[k_cubKey]{};
	for ( usize ib = 0; ib < k_cubKey; ++ib )
		rgubKey[ib] = pubKey[ib];
	DecryptBuffer( IceKey_t{ rgubKey }, pubIn, cubData, pubOut );
}

} // namespace vac::crypto::ice
