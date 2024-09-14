#pragma once
#include <sstream>
#include <string>

namespace snet::utils
{

namespace detail
{

template <typename T>
void formatHelper(std::ostringstream& oss, std::string_view& str,
                  const T& value)
{
    std::size_t openBracket = str.find('{');
    if (openBracket == std::string::npos)
    {
        return;
    }

    std::size_t closeBracket = str.find('}', openBracket + 1);
    if (closeBracket == std::string::npos)
    {
        return;
    }

    oss << str.substr(0, openBracket) << value;
    str = str.substr(closeBracket + 1);
}

} // namespace detail

template <typename... Args>
std::string format(std::string_view str, Args... args)
{
    std::ostringstream oss;
    (detail::formatHelper(oss, str, args), ...);
    oss << str;
    return oss.str();
}

} // namespace snet::utils