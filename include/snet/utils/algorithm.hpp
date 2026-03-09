#pragma once
#include <algorithm>
#include <casket/nonstd/span.hpp>

namespace snet
{

template <typename T>
inline bool ValueExists(nonstd::span<const T> values, const T& value)
{
    return std::find(values.begin(), values.end(), value) != values.end();
}

template <typename T>
inline bool ValueExists(const std::vector<T>& values, const T& value)
{
    return std::find(values.begin(), values.end(), value) != values.end();
}

} // namespace snet