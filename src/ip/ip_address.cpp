#include <snet/ip/ip_address.hpp>

namespace snet::ip
{

IPAddress::IPAddress() noexcept
    : type_(IPv4)
    , ipv4_()
    , ipv6_()
{
}

IPAddress::IPAddress(const IPv4Address& addr) noexcept
    : type_(IPv4)
    , ipv4_(addr)
    , ipv6_()
{
}

IPAddress::IPAddress(const IPv6Address& addr) noexcept
    : type_(IPv6)
    , ipv4_()
    , ipv6_(addr)
{
}

IPAddress::~IPAddress() = default;

IPAddress::IPAddress(const IPAddress& other) noexcept
    : type_(other.type_)
    , ipv4_(other.ipv4_)
    , ipv6_(other.ipv6_)
{
}

IPAddress::IPAddress(IPAddress&& other) noexcept
    : type_(other.type_)
    , ipv4_(other.ipv4_)
    , ipv6_(other.ipv6_)
{
}

IPAddress& IPAddress::operator=(const IPAddress& other) noexcept
{
    type_ = other.type_;
    ipv4_ = other.ipv4_;
    ipv6_ = other.ipv6_;
    return *this;
}

IPAddress& IPAddress::operator=(IPAddress&& other) noexcept
{
    type_ = other.type_;
    ipv4_ = other.ipv4_;
    ipv6_ = other.ipv6_;
    return *this;
}

IPAddress& IPAddress::operator=(const IPv4Address& other) noexcept
{
    type_ = IPv4;
    ipv4_ = other;
    ipv6_ = IPv6Address();
    return *this;
}

IPAddress& IPAddress::operator=(const IPv6Address& other) noexcept
{
    type_ = IPv6;
    ipv4_ = IPv4Address();
    ipv6_ = other;
    return *this;
}

std::string IPAddress::toString() const
{
    if (type_ == IPv6)
    {
        return ipv6_.toString();
    }
    return ipv4_.toString();
}



bool IPAddress::isIPv4() const noexcept
{
    return type_ == IPv4;
}

bool IPAddress::isIPv6() const noexcept
{
    return type_ == IPv6;
}

IPv4Address IPAddress::toIPv4() const
{
    if (type_ != IPv4)
    {
        throw std::bad_cast();
    }
    return ipv4_;
}

IPv6Address IPAddress::toIPv6() const
{
    if (type_ != IPv6)
    {
        throw std::bad_cast();
    }
    return ipv6_;
}

bool IPAddress::operator==(const IPAddress& rhs) const noexcept
{
    if (type_ != rhs.type_)
        return false;
    if (type_ == IPv6)
        return ipv6_ == rhs.ipv6_;
    return ipv4_ == rhs.ipv4_;
}

bool IPAddress::operator!=(const IPAddress& rhs) const noexcept
{
    return !(*this == rhs);
}

bool IPAddress::operator<(const IPAddress& rhs) const noexcept
{
    if (type_ < rhs.type_)
        return true;
    if (type_ > rhs.type_)
        return false;
    if (type_ == IPv6)
        return ipv6_ < rhs.ipv6_;
    return ipv4_ < rhs.ipv4_;
}

bool IPAddress::operator>(const IPAddress& rhs) const noexcept
{
    return rhs < *this;
}

bool IPAddress::operator<=(const IPAddress& rhs) const noexcept
{
    return !(rhs < *this);
}

bool IPAddress::operator>=(const IPAddress& rhs) const noexcept
{
    return !(*this < rhs);
}

IPAddress IPAddress::any() noexcept
{
    return IPAddress();
}

std::optional<IPAddress> IPAddress::fromString(const char* str)
{
    auto ipv6 = IPv6Address::fromString(str);
    if (ipv6.has_value())
        return IPAddress(ipv6.value());

    auto ipv4 = IPv4Address::fromString(str);
    if (ipv4.has_value())
        return IPAddress(ipv4.value());

    return std::nullopt;
}

} // namespace snet::ip

std::ostream& operator<<(std::ostream& os, const snet::ip::IPAddress& addr)
{
    os << addr.toString();
    return os;
}