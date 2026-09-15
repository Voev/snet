#pragma once
#include <cstdint>
#include <unordered_map>
#include <snet/layers/l3/ip_address.hpp>

namespace snet::tcp
{

struct TcpListener
{
    layers::IPAddress localIP;
    uint32_t backlog{128};
    uint32_t halfOpen{0};
    uint32_t established{0};
    uint16_t localPort{0};
    bool active{true};

    bool matches(const layers::IPAddress& dstIP, uint16_t dstPort) const noexcept
    {
        if (dstPort != localPort)
            return false;
        if (localIP == layers::IPAddress::any())
            return true;
        return localIP == dstIP;
    }
};

class TcpListenerRegistry
{
public:
    TcpListener* add(const layers::IPAddress& localIP, uint16_t localPort, uint32_t backlog = 128)
    {
        const uint64_t key = makeKey(localIP, localPort);
        auto it = listeners_.find(key);
        if (it != listeners_.end())
            return &it->second;

        TcpListener lst;
        lst.localIP = localIP;
        lst.localPort = localPort;
        lst.backlog = backlog;
        auto [ins, _] = listeners_.emplace(key, lst);
        return &ins->second;
    }

    TcpListener* find(const layers::IPAddress& dstIP, uint16_t dstPort)
    {
        auto it = listeners_.find(makeKey(dstIP, dstPort));
        if (it != listeners_.end() && it->second.active)
            return &it->second;

        auto iw = listeners_.find(makeKey(layers::IPAddress::any(), dstPort));
        if (iw != listeners_.end() && iw->second.active)
            return &iw->second;

        return nullptr;
    }

    void remove(const layers::IPAddress& localIP, uint16_t localPort)
    {
        listeners_.erase(makeKey(localIP, localPort));
    }

private:
    static uint64_t makeKey(const layers::IPAddress& ip, uint16_t port)
    {
        uint64_t h = 0;
        const uint8_t* p = ip.asData();
        for (int i = 0; i < 4; ++i)
            h = (h << 8) | p[i];
        return (h << 16) | port;
    }
    std::unordered_map<uint64_t, TcpListener> listeners_;
};

} // namespace snet::tcp