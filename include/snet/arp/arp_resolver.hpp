#pragma once

#include <snet/io/types.hpp>
#include <snet/io/device.hpp>

#include <snet/arp/i_arp_transport.hpp>
#include <snet/layers/packet.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <unordered_map>

#include <casket/nonstd/optional.hpp>

namespace snet::arp
{

class ArpResolver
{
public:
    using Clock = std::chrono::steady_clock;
    using DeviceId = snet::io::DeviceId;
    using MacAddress = snet::layers::MacAddress;
    using IPv4Address = snet::layers::IPv4Address;
    using Packet = snet::layers::Packet;

    explicit ArpResolver(IArpTransport& transport, std::chrono::milliseconds retry = std::chrono::milliseconds(1000),
                         int maxRetries = 3);

    void addLocal(DeviceId iface, const IPv4Address& ip, const MacAddress& mac);

    nonstd::optional<MacAddress> lookup(DeviceId iface, const IPv4Address& ip) const;

    void observe(DeviceId iface, const IPv4Address& ip, const MacAddress& mac);

    void request(DeviceId iface, const IPv4Address& ip);

    bool handle(Packet* packet, DeviceId iface);

    void tick();

private:
    struct Key
    {
        DeviceId iface;
        IPv4Address ip;
        bool operator==(const Key&) const = default;
    };

    struct KeyHash
    {
        size_t operator()(const Key& k) const noexcept
        {
            const uint32_t net = k.ip.toNetwork();
            return std::hash<uint64_t>{}((static_cast<uint64_t>(k.iface) << 32) ^ net);
        }
    };

    struct Entry
    {
        std::optional<MacAddress> mac;
        Clock::time_point nextProbe{};
        int retries{0};
    };

    struct LocalEntry
    {
        IPv4Address ip;
        MacAddress mac;
    };

    void sendProbe(const Key& key);

    IArpTransport& transport_;
    std::chrono::milliseconds retry_;
    int maxRetries_;
    std::unordered_map<Key, Entry, KeyHash> table_;
    std::unordered_map<DeviceId, LocalEntry> local_;
};

} // namespace snet::arp