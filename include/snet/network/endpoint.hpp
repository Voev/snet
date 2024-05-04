#pragma once
#include <sstream>
#include <snet/network/ip_address.hpp>
#include <snet/network/types.hpp>

namespace snet::network
{

// Helper class for implementating an IP Endpoint.
class Endpoint
{
public:
    // Default constructor.
    Endpoint() noexcept
        : data_{}
    {
        data_.v4.sin_family = AF_INET;
        data_.v4.sin_port = 0;
        data_.v4.sin_addr.s_addr = INADDR_ANY;
    }

    // Construct an Endpoint using a family and port number.
    Endpoint(int family, std::uint16_t port) noexcept
    {
        if (family == AF_INET)
        {
            data_.v4.sin_family = AF_INET;
            data_.v4.sin_port = htons(port);
            data_.v4.sin_addr.s_addr = INADDR_ANY;
        }
        else
        {
            data_.v6.sin6_family = AF_INET6;
            data_.v6.sin6_port = htons(port);
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

    // Construct an Endpoint using an address and port number.
    Endpoint(const IPAddress& addr, std::uint16_t port) noexcept
    {
        if (addr.isIPv4())
        {
            data_.v4.sin_family = AF_INET;
            data_.v4.sin_port = htons(port);
            data_.v4.sin_addr.s_addr = htonl(addr.toIPv4().toUint());
        }
        else
        {
            data_.v6.sin6_family = AF_INET6;
            data_.v6.sin6_port = htons(port);
            data_.v6.sin6_flowinfo = 0;
            auto ipv6 = addr.toIPv6();
            auto bytes = ipv6.toBytes();
            std::memcpy(data_.v6.sin6_addr.s6_addr, bytes.data(),
                        IPv6Address::kBytesCount);
            data_.v6.sin6_scope_id = 0;
        }
    }

    // Copy constructor.
    Endpoint(const Endpoint& other) noexcept
        : data_(other.data_)
    {
    }

    // Assign from another Endpoint.
    Endpoint& operator=(const Endpoint& other) noexcept
    {
        data_ = other.data_;
        return *this;
    }

    int family() const noexcept
    {
        if (isIPv4())
            return data_.v4.sin_family;
        else
            return data_.v6.sin6_family;
    }

    // Get the underlying Endpoint in the native type.
    socket_addr_type* data() noexcept
    {
        return &data_.base;
    }

    // Get the underlying Endpoint in the native type.
    const socket_addr_type* data() const noexcept
    {
        return &data_.base;
    }

    // Get the underlying size of the Endpoint in the native type.
    std::size_t size() const noexcept
    {
        if (isIPv4())
            return sizeof(sockaddr_in4_type);
        else
            return sizeof(sockaddr_in6_type);
    }

    // Get the capacity of the Endpoint in the native type.
    std::size_t capacity() const noexcept
    {
        return sizeof(data_);
    }

    // Get the port associated with the Endpoint.
    std::uint16_t port() const noexcept
    {
        if (isIPv4())
        {
            return ntohs(data_.v4.sin_port);
        }
        else
        {
            return ntohs(data_.v6.sin6_port);
        }
    }

    // Set the port associated with the Endpoint.
    void port(std::uint16_t port) noexcept
    {
        if (isIPv4())
        {
            data_.v4.sin_port = htons(port);
        }
        else
        {
            data_.v6.sin6_port = htons(port);
        }
    }

    // Get the IP address associated with the Endpoint.
    IPAddress address() const noexcept
    {
        if (isIPv4())
        {
            return IPv4Address(ntohs(data_.v4.sin_addr.s_addr));
        }
        else
        {
            IPv6Address::BytesType bytes;
            std::memcpy(bytes.data(), data_.v6.sin6_addr.s6_addr,
                        IPv6Address::kBytesCount);
            return IPv6Address(bytes);
        }
    }

    // Set the IP address associated with the Endpoint.
    inline void address(const IPAddress& addr) noexcept
    {
        Endpoint tmp(addr, port());
        data_ = tmp.data_;
    }

    // Compare two Endpoints for equality.
    inline friend bool operator==(const Endpoint& e1,
                                  const Endpoint& e2) noexcept
    {
        return e1.address() == e2.address() && e1.port() == e2.port();
    }

    // Compare Endpoints for ordering.
    inline friend bool operator<(const Endpoint& e1,
                                 const Endpoint& e2) noexcept
    {
        if (e1.address() < e2.address())
            return true;
        if (e1.address() != e2.address())
            return false;
        return e1.port() < e2.port();
    }

    // Determine whether the Endpoint is IPv4.
    inline bool isIPv4() const noexcept
    {
        return data_.base.sa_family == AF_INET;
    }

    std::string toString() const
    {
        std::ostringstream os;
        if (isIPv4())
            os << address();
        else
            os << '[' << address() << ']';
        os << ':' << port();
        return os.str();
    }

private:
    // The underlying IP socket address.
    union data_union
    {
        socket_addr_type base;
        sockaddr_in4_type v4;
        sockaddr_in6_type v6;
    } data_;
};

} // namespace snet::network

template <> struct std::hash<snet::network::Endpoint>
{
    std::size_t operator()(const snet::network::Endpoint& ep) const noexcept
    {
        std::size_t hash1 = std::hash<snet::network::IPAddress>()(ep.address());
        std::size_t hash2 = std::hash<std::uint16_t>()(ep.port());
        return hash1 ^ (hash2 + 0x9e3779b9 + (hash1 << 6) + (hash1 >> 2));
    }
};
