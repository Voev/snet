#include <snet/tls/version.hpp>
#include <casket/utils/string.hpp>

namespace snet::tls
{

std::string ProtocolVersion::toString() const
{
    const uint8_t maj = majorVersion();
    const uint8_t min = minorVersion();

    if (maj == 3 && min == 0)
    {
        return "SSLv3.0";
    }

    if (maj == 3 && min >= 1)
    {
        return "TLSv1." + std::to_string(min - 1);
    }

    return "Unknown version " + std::to_string(maj) + "." + std::to_string(min);
}

std::optional<ProtocolVersion> ProtocolVersion::fromString(std::string_view str)
{
    if (casket::iequals(str, "sslv3.0"))
    {
        return VersionCode::SSLv3_0;
    }
    else if (casket::iequals(str, "tlsv1.0"))
    {
        return VersionCode::TLSv1_0;
    }
    else if (casket::iequals(str, "tlsv1.1"))
    {
        return VersionCode::TLSv1_1;
    }
    else if (casket::iequals(str, "tlsv1.2"))
    {
        return VersionCode::TLSv1_2;
    }
    else if (casket::iequals(str, "tlsv1.3"))
    {
        return VersionCode::TLSv1_3;
    }
    return std::nullopt;
}

std::optional<ProtocolVersionRange> ParseProtocolVersionRange(std::string_view str)
{
    auto delim = str.find("-");
    if (delim != std::string_view::npos)
    {
        auto first = str.substr(0, delim);
        auto second = str.substr(delim + 1);

        auto firstVersion = ProtocolVersion::fromString(first);
        auto secondVersion = ProtocolVersion::fromString(second);

        if (firstVersion.has_value() && secondVersion.has_value())
            return std::make_pair(firstVersion.value(), secondVersion.value());
        return std::nullopt;
    }

    auto version = ProtocolVersion::fromString(str);
    if (version.has_value())
        return std::make_pair(version.value(), version.value());
    return std::nullopt;
}

} // namespace snet::tls