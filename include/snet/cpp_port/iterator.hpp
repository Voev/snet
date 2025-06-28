#pragma once

#if __cplusplus < 201703L

#include "nodiscard.hpp"
#include <cstdint>

namespace nonstd2
{

template <class _Container>
NONSTD_NODISCARD constexpr auto size( const _Container& _Cont )
     -> decltype( _Cont.size() )
{
     return ( _Cont.size() );
}

template <class _Ty,
          size_t _Size>
NONSTD_NODISCARD constexpr size_t size( const _Ty ( & )[_Size] ) noexcept
{
     return ( _Size );
}

} // namespace nonstd2

#else // ^^^ if __cplusplus < 201703L ^^^ / vvv if __cplusplus >= 201703L vvv

#include <iterator>

#endif // __cplusplus < 201703L
