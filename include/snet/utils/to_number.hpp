#pragma once
#include <charconv>
#include <system_error>
#include <string_view>
#include <type_traits>

#include <snet/utils/exception.hpp>

namespace snet::utils
{

template <typename T>
inline void to_number(std::string_view value, T& result, std::error_code& ec)
{
    static_assert(std::is_integral_v<T> == true);
    auto r = std::from_chars(value.data(), value.data() + value.size(), result);
    if (r.ec != std::errc())
    {
        ec = std::make_error_code(r.ec);
    }
}

template <typename T>
inline void to_number(std::string_view value, T& result)
{
    std::error_code ec;
    to_number<T>(value, result, ec);
    utils::ThrowIfError(ec);
}

} // namespace snet::utils
