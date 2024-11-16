#pragma once
#include <snet/ip/ip_address.hpp>
#include <snet/tls/types.hpp>

namespace snet::tls
{

class ServerInfo final
{
public:
    ServerInfo()
        : hostname_()
        , address_()
        , port_(0)
    {
    }

    ~ServerInfo() noexcept
    {
    }

    void setIPAddress(ip::IPAddress address) noexcept
    {
        address_ = std::move(address);
    }

    const ip::IPAddress getIPAddress() const noexcept
    {
        return address_;
    }

    void setHostname(std::string hostname) noexcept
    {
        hostname_ = std::move(hostname);
    }

    const std::string& getHostname() const noexcept
    {
        return hostname_;
    }

    void setServerKey(EVP_PKEY* serverKey)
    {
        if (!serverKey || !EVP_PKEY_up_ref(serverKey))
        {
            throw std::runtime_error("All is bad!");
        }
        serverKey_.reset(serverKey);
    }

    EVP_PKEY* getServerKey() const noexcept
    {
        return serverKey_.get();
    }

private:
    std::string hostname_;
    ip::IPAddress address_;
    std::uint16_t port_;
    EvpPkeyPtr serverKey_;
};

} // namespace snet::tls