#pragma once
#include <string>
#include <snet/ip/ip_address.hpp>

namespace snet::sniffer {

class ServerInfo final {
public:
    ServerInfo()
        : hostname_()
        , address_()
        , port_(0) {
    }

    explicit ServerInfo(std::string hostname, ip::IPAddress address, uint16_t port)
        : hostname_(std::move(hostname))
        , address_(std::move(address))
        , port_(port) {
    }

    explicit ServerInfo(std::string hostname, uint16_t port)
        : hostname_(std::move(hostname))
        , address_()
        , port_(port) {
    }

    explicit ServerInfo(ip::IPAddress address, uint16_t port)
        : hostname_()
        , address_(std::move(address))
        , port_(port) {
    }

    const std::string& hostname() const {
        return hostname_;
    }

    const ip::IPAddress& address() const {
        return address_;
    }

    uint16_t port() const {
        return port_;
    }

private:
    std::string hostname_;
    ip::IPAddress address_;
    uint16_t port_;
};

inline bool operator==(const ServerInfo& a, const ServerInfo& b) {
    return (a.hostname() == b.hostname()) && (a.address() == b.address()) && (a.port() == b.port());
}

inline bool operator!=(const ServerInfo& a, const ServerInfo& b) {
    return !(a == b);
}

inline bool operator<(const ServerInfo& a, const ServerInfo& b) {
    if (a.hostname() != b.hostname()) {
        return (a.hostname() < b.hostname());
    }
    if (a.address() != b.address()) {
        return (a.address() < b.address());
    }
    if (a.port() != b.port()) {
        return (a.port() < b.port());
    }
    return false; // equal
}

} // namespace snet
