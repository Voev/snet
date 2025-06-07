#pragma once
#include <vector>

namespace snet
{

template <typename T>
inline bool contains(const std::vector<T>& v, const T& x)
{
    return std::find(v.begin(), v.end(), x) != v.end();
}

} // namespace snet