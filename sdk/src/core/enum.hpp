#pragma once

#include <type_traits>

#define VAC_FLAGS( EFlags )                                                                                            \
	constexpr EFlags operator|( EFlags eLeft, EFlags eRight ) noexcept                                                 \
	{                                                                                                                  \
		using Underlying_t = std::underlying_type_t<EFlags>;                                                           \
		return static_cast<EFlags>( static_cast<Underlying_t>( eLeft ) | static_cast<Underlying_t>( eRight ) );        \
	}                                                                                                                  \
	constexpr EFlags operator&( EFlags eLeft, EFlags eRight ) noexcept                                                 \
	{                                                                                                                  \
		using Underlying_t = std::underlying_type_t<EFlags>;                                                           \
		return static_cast<EFlags>( static_cast<Underlying_t>( eLeft ) & static_cast<Underlying_t>( eRight ) );        \
	}                                                                                                                  \
	constexpr EFlags &operator|=( EFlags &eLeft, EFlags eRight ) noexcept                                              \
	{                                                                                                                  \
		return eLeft = eLeft | eRight;                                                                                 \
	}                                                                                                                  \
	constexpr bool HasFlag( EFlags eValue, EFlags eFlag ) noexcept                                                     \
	{                                                                                                                  \
		return static_cast<std::underlying_type_t<EFlags>>( eValue & eFlag ) != 0;                                     \
	}
