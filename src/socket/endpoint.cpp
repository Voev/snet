#include <algorithm>
#include <snet/socket/endpoint.hpp>
#include <casket/utils/endianness.hpp>

using namespace casket;
using namespace snet::layers;

namespace snet::socket
{

Endpoint::Endpoint() noexcept
    : data_{}
{
    data_.v4.sin_family = AF_INET;
    data_.v4.sin_port = 0;
    data_.v4.sin_addr.s_addr = INADDR_ANY;
}

Endpoint::Endpoint(int family, std::uint16_t port) noexcept
{
    if (family == AF_INET)
    {
        data_.v4.sin_family = AF_INET;
        data_.v4.sin_port = host_to_be(port);
        data_.v4.sin_addr.s_addr = INADDR_ANY;
    }
    else
    {
        data_.v6.sin6_family = AF_INET6;
        data_.v6.sin6_port = host_to_be(port);
        data_.v6.sin6_flowinfo = 0;
        data_.v6.sin6_addr.s6_addr[0] = 0;
        data_.v6.sin6_addr.s6_addr[1] = 0;
        data_.v6.sin6_addr.s6_addr[2] = 0;
        data_.v6.sin6_addr.s6_addr[3] = 0;
        data_.v6.sin6_addr.s6_addr[4] = 0;
        data_.v6.sin6_addr.s6_addr[5] = 0;
        data_.v6.sin6_addr.s6_addr[6] = 0;
        data_.v6.sin6_addr.s6_addr[7] = 0;
        data_.v6.sin6_addr.s6_addr[8] = 0;
        data_.v6.sin6_addr.s6_addr[9] = 0;
        data_.v6.sin6_addr.s6_addr[10] = 0;
        data_.v6.sin6_addr.s6_addr[11] = 0;
        data_.v6.sin6_addr.s6_addr[12] = 0;
        data_.v6.sin6_addr.s6_addr[13] = 0;
        data_.v6.sin6_addr.s6_addr[14] = 0;
        data_.v6.sin6_addr.s6_addr[15] = 0;
        data_.v6.sin6_scope_id = 0;
    }
}

Endpoint::Endpoint(const IPAddress& addr, std::uint16_t port) noexcept
{
    if (addr.isIPv4())
    {
        data_.v4.sin_family = AF_INET;
        data_.v4.sin_port = host_to_be(port);
        data_.v4.sin_addr.s_addr = host_to_be(addr.toIPv4().toUint());
    }
    else
    {
        data_.v6.sin6_family = AF_INET6;
        data_.v6.sin6_port = host_to_be(port);
        data_.v6.sin6_flowinfo = 0;
        auto ipv6 = addr.toIPv6();
        std::copy(ipv6.begin(), ipv6.end(),
                  std::begin(data_.v6.sin6_addr.s6_addr));
        data_.v6.sin6_scope_id = 0;
    }
}

Endpoint::Endpoint(const Endpoint& other) noexcept
    : data_(other.data_)
{
}

Endpoint& Endpoint::operator=(const Endpoint& other) noexcept
{
    data_ = other.data_;
    return *this;
}

int Endpoint::family() const noexcept
{
    if (isIPv4())
        return data_.v4.sin_family;
    else
        return data_.v6.sin6_family;
}

SocketAddrType* Endpoint::data() noexcept
{
    return &data_.base;
}

const SocketAddrType* Endpoint::data() const noexcept
{
    return &data_.base;
}

std::size_t Endpoint::size() const noexcept
{
    if (isIPv4())
        return sizeof(SockAddrIn4Type);
    else
        return sizeof(SockAddrIn6Type);
}

std::size_t Endpoint::capacity() const noexcept
{
    return sizeof(data_);
}

std::uint16_t Endpoint::port() const noexcept
{
    if (isIPv4())
    {
        return be_to_host(data_.v4.sin_port);
    }
    else
    {
        return be_to_host(data_.v6.sin6_port);
    }
}

void Endpoint::port(std::uint16_t port) noexcept
{
    if (isIPv4())
    {
        data_.v4.sin_port = host_to_be(port);
    }
    else
    {
        data_.v6.sin6_port = host_to_be(port);
    }
}

IPAddress Endpoint::address() const noexcept
{
    if (isIPv4())
    {
        return IPv4Address(be_to_host(data_.v4.sin_addr.s_addr));
    }
    else
    {
        std::array<uint8_t, IPv6Address::kBytesCount> ip;
        std::copy_n(data_.v6.sin6_addr.s6_addr, IPv6Address::kBytesCount, ip.begin());
        return IPv6Address(ip);
    }
}

void Endpoint::address(const IPAddress& addr) noexcept
{
    Endpoint tmp(addr, port());
    data_ = tmp.data_;
}

bool Endpoint::operator==(const Endpoint& rhs) const noexcept
{
    return address() == rhs.address() && port() == rhs.port();
}

bool Endpoint::operator<(const Endpoint& rhs) const noexcept
{
    if (address() < rhs.address())
        return true;
    if (address() != rhs.address())
        return false;
    return port() < rhs.port();
}

bool Endpoint::isIPv4() const noexcept
{
    return data_.base.sa_family == AF_INET;
}

std::string Endpoint::toString() const
{
    std::ostringstream os;
    if (isIPv4())
        os << address();
    else
        os << '[' << address() << ']';
    os << ':' << port();
    return os.str();
}

} // namespace snet::socket
