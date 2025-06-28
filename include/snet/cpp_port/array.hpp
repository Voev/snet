#pragma once

#include "type_traits.hpp"
#include "nodiscard.hpp"

#include <array>

#if _HAS_CXX20
#   pragma error( "Remove me!" )
#else

namespace nonstd2
{

namespace detail
{

template <class _Ty, size_t _Size, size_t... _Idx>
NONSTD_NODISCARD constexpr std::array<std::remove_cv_t<_Ty>, _Size> ToArrayLvalueImpl( _Ty ( &_Array )[_Size], std::index_sequence<_Idx...> )
{
     return { { _Array[_Idx]... } };
}

template <class _Ty, size_t _Size, size_t... _Idx>
NONSTD_NODISCARD constexpr std::array<std::remove_cv_t<_Ty>, _Size> ToArrayRvalueImpl( _Ty( &&_Array )[_Size], std::index_sequence<_Idx...> )
{
     return { { std::move( _Array[_Idx] )... } };
}
} // namespace detail

template <class _Ty, size_t _Size>
NONSTD_NODISCARD constexpr std::array<std::remove_cv_t<_Ty>, _Size> to_array( _Ty ( &_Array )[_Size] )
{
     static_assert( !nonstd2::is_array_v<_Ty>, "N4830 [array.creation]/1: "
                                           "to_array does not accept multidimensional arrays." );
     static_assert( nonstd2::is_constructible_v<_Ty, _Ty&>, "N4830 [array.creation]/1: "
                                                        "to_array requires copy constructible elements." );
     return nonstd2::detail::ToArrayLvalueImpl( _Array, std::make_index_sequence<_Size>{} );
}

template <class _Ty, size_t _Size>
NONSTD_NODISCARD constexpr std::array<std::remove_cv_t<_Ty>, _Size> to_array( _Ty( &&_Array )[_Size] )
{
     static_assert( !nonstd2::is_array_v<_Ty>, "N4830 [array.creation]/4: "
                                           "to_array does not accept multidimensional arrays." );
     static_assert( nonstd2::is_move_constructible_v<_Ty>, "N4830 [array.creation]/4: "
                                                       "to_array requires move constructible elements." );
     return nonstd2::detail::ToArrayRvalueImpl( std::move( _Array ), std::make_index_sequence<_Size>{} );
}

} // namespace nonstd2

#endif // !_HAS_CXX20
