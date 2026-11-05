#pragma once

#include <cstddef>

#define VAC_LAYOUT( Type, Field, Offset )                                                                              \
	static_assert( offsetof( Type, Field ) == ( Offset ), #Type "::" #Field " moved" )

#define VAC_LAYOUT_SIZE( Type, Size ) static_assert( sizeof( Type ) == ( Size ), #Type " size changed" )
