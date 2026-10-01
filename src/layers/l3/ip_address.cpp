#include <snet/layers/l3/ip_address.hpp>

namespace snet::layers
{

IPAddress::IPAddress() noexcept
    : ip_(IPv4Address{})
{}

IPAddress::IPAddress(const IPv4Address& addr) noexcept
    : ip_(addr)
{
}

IPAddress::IPAddress(const IPv6Address& addr) noexcept
    : ip_(addr)
{
}

IPAddress::~IPAddress() = default;

IPAddress::IPAddress(const IPAddress& other) noexcept
    : ip_(other.ip_)
{
}

IPAddress::IPAddress(IPAddress&& other) noexcept
    : ip_(std::move(other.ip_))
{
}

IPAddress& IPAddress::operator=(const IPAddress& other) noexcept
{
    ip_ = other.ip_;
    return *this;
}

IPAddress& IPAddress::operator=(IPAddress&& other) noexcept
{
    ip_ = std::move(other.ip_);
    return *this;
}

IPAddress& IPAddress::operator=(const IPv4Address& other) noexcept
{
    ip_ = other;
    return *this;
}

IPAddress& IPAddress::operator=(const IPv6Address& other) noexcept
{
    ip_ = other;
    return *this;
}

std::string IPAddress::toString() const
{
    return nonstd::visit([](const auto& addr) { return addr.toString(); }, ip_);
}

bool IPAddress::isIPv4() const noexcept
{
    return nonstd::holds_alternative<IPv4Address>(ip_);
}

bool IPAddress::isIPv6() const noexcept
{
    return nonstd::holds_alternative<IPv6Address>(ip_);
}

IPv4Address IPAddress::toIPv4() const
{
    return nonstd::get<IPv4Address>(ip_);
}

IPv6Address IPAddress::toIPv6() const
{
    return nonstd::get<IPv6Address>(ip_);
}

bool IPAddress::operator==(const IPAddress& rhs) const noexcept
{
    return ip_ == rhs.ip_;
}

bool IPAddress::operator!=(const IPAddress& rhs) const noexcept
{
    return !(*this == rhs);
}

bool IPAddress::operator<(const IPAddress& rhs) const noexcept
{
    return ip_ < rhs.ip_;
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

IPAddress IPAddress::any(bool ipv4) noexcept
{
    if (ipv4)
        return IPAddress(IPv4Address::any());
    return IPAddress(IPv6Address::any());
}

nonstd::optional<IPAddress> IPAddress::fromString(const char* str)
{
    auto ipv6 = IPv6Address::fromString(str);
    if (ipv6.has_value())
        return IPAddress(ipv6.value());

    auto ipv4 = IPv4Address::fromString(str);
    if (ipv4.has_value())
        return IPAddress(ipv4.value());

    return std::nullopt;
}

} // namespace snet::layers
