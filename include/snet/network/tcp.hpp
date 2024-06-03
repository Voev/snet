#pragma once
#include <snet/network/types.hpp>

namespace snet::network
{

/// Encapsulates the flags needed for TCP.
/**
 * The asio::ip::Tcp class contains flags necessary for TCP sockets.
 *
 * @par Thread Safety
 * @e Distinct @e objects: Safe.@n
 * @e Shared @e objects: Safe.
 *
 * @par Concepts:
 * Protocol, InternetProtocol.
 */
class Tcp
{
public:
    /// Construct to represent the IPv4 TCP protocol.
    static Tcp v4() noexcept
    {
        return Tcp(AF_INET);
    }

    /// Construct to represent the IPv6 TCP protocol.
    static Tcp v6() noexcept
    {
        return Tcp(AF_INET6);
    }

    /// Obtain an identifier for the type of the protocol.
    int type() const noexcept
    {
        return SOCK_STREAM;
    }

    /// Obtain an identifier for the protocol.
    int protocol() const noexcept
    {
        return IPPROTO_TCP;
    }

    /// Obtain an identifier for the protocol family.
    int family() const noexcept
    {
        return family_;
    }

    /// Compare two protocols for equality.
    friend bool operator==(const Tcp& p1, const Tcp& p2)
    {
        return p1.family_ == p2.family_;
    }

    /// Compare two protocols for inequality.
    friend bool operator!=(const Tcp& p1, const Tcp& p2)
    {
        return p1.family_ != p2.family_;
    }

private:
    // Construct with a specific family.
    explicit Tcp(int protocol_family) noexcept
        : family_(protocol_family)
    {
    }

    int family_;
};

} // namespace snet::network