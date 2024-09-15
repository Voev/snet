#pragma once
#include <algorithm>
#include <string_view>

namespace snet::utils
{

static inline bool equals(std::string_view a, std::string_view b)
{
    return std::equal(a.begin(), a.end(), b.begin(), b.end());
}

static inline bool iequals(std::string_view a, std::string_view b)
{
    auto compare = [](char x, char y) -> bool {
        return std::tolower(static_cast<unsigned char>(x)) ==
               std::tolower(static_cast<unsigned char>(y));
    };
    return std::equal(a.begin(), a.end(), b.begin(), b.end(), compare);
}

} // namespace snet::utils