#include <snet/tls/tls_utils.hpp>
#include <snet/utils/string.hpp>

namespace snet::tls
{

std::optional<VersionCode> ParseVersion(std::string_view str)
{
    if (utils::iequals(str, "ssl2"))
    {
        return VersionCode::SSLv2_0;
    }
    else if (utils::iequals(str, "ssl3"))
    {
        return VersionCode::SSLv3_0;
    }
    else if (utils::iequals(str, "tls1"))
    {
        return VersionCode::TLSv1_0;
    }
    else if (utils::iequals(str, "tls1.1"))
    {
        return VersionCode::TLSv1_1;
    }
    else if (utils::iequals(str, "tls1.2"))
    {
        return VersionCode::TLSv1_2;
    }
    else if (utils::iequals(str, "tls1.3"))
    {
        return VersionCode::TLSv1_3;
    }
    return std::nullopt;
}

std::optional<VersionCodeRange> ParseVersionRange(std::string_view str)
{
    auto delim = str.find("-");
    if (delim != std::string_view::npos)
    {
        auto first = str.substr(0, delim);
        auto second = str.substr(delim + 1);
        
        auto firstVersion = ParseVersion(first);
        auto secondVersion = ParseVersion(second);
        
        if (firstVersion.has_value() && secondVersion.has_value())
            return std::make_pair(firstVersion.value(), secondVersion.value());
        return std::nullopt;
    }

    auto version = ParseVersion(str);
    if (version.has_value())
        return std::make_pair(version.value(), version.value());
    return std::nullopt;
}

} // namespace snet::tls