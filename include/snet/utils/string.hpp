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

template <typename String>
inline std::vector<String> split(const String& str, const String& delim) {
    size_t start = 0;
    size_t end = String::npos;
    size_t delimLen = delim.length();

    String token;
    std::vector<String> res;

    while ((end = str.find(delim, start)) != String::npos) {
        token = str.substr(start, end - start);
        start = end + delimLen;
        res.push_back(token);
    }

    res.push_back(str.substr(start));
    return res;
}

} // namespace snet::utils