#pragma once
#include <sstream>
#include <snet/ip/ip_address.hpp>
#include <snet/socket/types.hpp>

namespace snet::socket
{

// Helper class for implementating an IP Endpoint.
class Endpoint
{
public:
    // Default constructor.
    Endpoint() noexcept;

    // Construct an Endpoint using a family and port number.
    Endpoint(int family, std::uint16_t port) noexcept;

    // Construct an Endpoint using an address and port number.
    Endpoint(const ip::IPAddress& addr, std::uint16_t port) noexcept;

    // Copy constructor.
    Endpoint(const Endpoint& other) noexcept;

    // Assign from another Endpoint.
    Endpoint& operator=(const Endpoint& other) noexcept;

    int family() const noexcept;

    // Get the underlying Endpoint in the native type.
    SocketAddrType* data() noexcept;

    // Get the underlying Endpoint in the native type.
    const SocketAddrType* data() const noexcept;

    // Get the underlying size of the Endpoint in the native type.
    std::size_t size() const noexcept;

    // Get the capacity of the Endpoint in the native type.
    std::size_t capacity() const noexcept;

    // Get the port associated with the Endpoint.
    std::uint16_t port() const noexcept;

    // Set the port associated with the Endpoint.
    void port(std::uint16_t port) noexcept;

    // Get the IP address associated with the Endpoint.
    ip::IPAddress address() const noexcept;

    // Set the IP address associated with the Endpoint.
    void address(const ip::IPAddress& addr) noexcept;

    // Compare two Endpoints for equality.
    bool operator==(const Endpoint& rhs) const noexcept;

    // Compare Endpoints for ordering.
    bool operator<(const Endpoint& rhs) const noexcept;

    // Determine whether the Endpoint is IPv4.
    bool isIPv4() const noexcept;

    std::string toString() const;

private:
    // The underlying IP ip address.
    union data_union
    {
        SocketAddrType base;
        SockAddrIn4Type v4;
        SockAddrIn6Type v6;
    } data_;
};

} // namespace snet::ip

template <> struct std::hash<snet::socket::Endpoint>
{
    std::size_t operator()(const snet::socket::Endpoint& ep) const noexcept
    {
        std::size_t hash1 = std::hash<snet::ip::IPAddress>()(ep.address());
        std::size_t hash2 = std::hash<std::uint16_t>()(ep.port());
        return hash1 ^ (hash2 + 0x9e3779b9 + (hash1 << 6) + (hash1 >> 2));
    }
};