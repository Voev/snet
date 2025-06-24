#include <casket/utils/string.hpp>
#include <snet/tls/version.hpp>

using namespace casket;

namespace snet::tls
{

ProtocolVersion::ProtocolVersion()
    : version_(0)
{
}

ProtocolVersion::~ProtocolVersion() noexcept = default;

ProtocolVersion::ProtocolVersion(const ProtocolVersion& other) = default;

ProtocolVersion::ProtocolVersion(ProtocolVersion&& other) noexcept = default;

ProtocolVersion& ProtocolVersion::operator=(const ProtocolVersion& other) = default;

ProtocolVersion& ProtocolVersion::operator=(ProtocolVersion&& other) noexcept = default;

ProtocolVersion::ProtocolVersion(uint16_t code)
    : version_(code)
{
}

ProtocolVersion::ProtocolVersion(VersionCode version)
    : ProtocolVersion(static_cast<uint16_t>(version))
{
}

ProtocolVersion::ProtocolVersion(uint8_t major, uint8_t minor)
    : ProtocolVersion(static_cast<uint16_t>((static_cast<uint16_t>(major) << 8) | minor))
{
}

uint8_t ProtocolVersion::majorVersion() const noexcept
{
    return static_cast<uint8_t>(version_ >> 8);
}

uint8_t ProtocolVersion::minorVersion() const noexcept
{
    return static_cast<uint8_t>(version_ & 0xFF);
}

uint16_t ProtocolVersion::code() const noexcept
{
    return version_;
}

std::string ProtocolVersion::toString() const
{
    const uint8_t maj = majorVersion();
    const uint8_t min = minorVersion();

    if (maj == 3 && min == 0)
    {
        return "SSLv3";
    }

    if (maj == 3 && min >= 1)
    {
        return "TLSv1." + std::to_string(min - 1);
    }

    if (maj == 254)
    {
        return "DTLSv1." + std::to_string(255 - min);
    }

    return "Unknown version " + std::to_string(maj) + "." + std::to_string(min);
}

std::optional<ProtocolVersion> ProtocolVersion::fromString(std::string_view str)
{
    if (utils::iequals(str, "sslv3.0"))
    {
        return VersionCode::SSLv3_0;
    }
    else if (utils::iequals(str, "tlsv1.0"))
    {
        return VersionCode::TLSv1_0;
    }
    else if (utils::iequals(str, "tlsv1.1"))
    {
        return VersionCode::TLSv1_1;
    }
    else if (utils::iequals(str, "tlsv1.2"))
    {
        return VersionCode::TLSv1_2;
    }
    else if (utils::iequals(str, "tlsv1.3"))
    {
        return VersionCode::TLSv1_3;
    }
    return std::nullopt;
}

bool ProtocolVersion::operator==(const ProtocolVersion& other) const noexcept
{
    return (version_ == other.version_);
}

bool ProtocolVersion::operator!=(const ProtocolVersion& other) const noexcept
{
    return (version_ != other.version_);
}

bool ProtocolVersion::operator>(const ProtocolVersion& other) const noexcept
{
    return version_ > other.version_;
}

bool ProtocolVersion::operator>=(const ProtocolVersion& other) const noexcept
{
    return (*this == other || *this > other);
}

bool ProtocolVersion::operator<(const ProtocolVersion& other) const noexcept
{
    return !(*this >= other);
}

bool ProtocolVersion::operator<=(const ProtocolVersion& other) const noexcept
{
    return (*this == other || *this < other);
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