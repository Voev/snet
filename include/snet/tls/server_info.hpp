/// @file
/// @brief Declaration of the ServerInfo class.

#pragma once
#include <snet/crypto/pointers.hpp>
#include <snet/ip/ip_address.hpp>
#include <snet/tls/types.hpp>

namespace snet::tls
{

/// @brief Class representing server information.
class ServerInfo final
{
public:
    /// @brief Default constructor.
    ServerInfo()
        : hostname_()
        , address_()
    {
    }

    /// @brief Destructor.
    ~ServerInfo() noexcept
    {
    }

    /// @brief Sets the IP address of the server.
    /// @param address The IP address to set.
    void setIPAddress(ip::IPAddress address) noexcept
    {
        address_ = std::move(address);
    }

    /// @brief Gets the IP address of the server.
    /// @return The IP address of the server.
    const ip::IPAddress getIPAddress() const noexcept
    {
        return address_;
    }

    /// @brief Sets the hostname of the server.
    /// @param hostname The hostname to set.
    void setHostname(std::string hostname) noexcept
    {
        hostname_ = std::move(hostname);
    }

    /// @brief Gets the hostname of the server.
    /// @return The hostname of the server.
    const std::string& getHostname() const noexcept
    {
        return hostname_;
    }

    /// @brief Sets the server key.
    /// @param serverKey The server key to set.
    void setServerKey(EVP_PKEY* serverKey)
    {
        if (!serverKey || !EVP_PKEY_up_ref(serverKey))
        {
            throw std::runtime_error("All is bad!");
        }
        serverKey_.reset(serverKey);
    }

    /// @brief Gets the server key.
    /// @return The server key.
    EVP_PKEY* getServerKey() const noexcept
    {
        return serverKey_.get();
    }

private:
    std::string hostname_;
    ip::IPAddress address_;
    crypto::KeyPtr serverKey_;
};

} // namespace snet::tls