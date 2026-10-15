#include <snet/arp/arp_resolver.hpp>

#include <snet/layers/l2/eth_header.hpp>
#include <snet/layers/l2/arp_header.hpp>

#include <casket/utils/endianness.hpp>

#include <cstring>

using namespace snet::io;
using namespace snet::layers;

namespace snet::arp
{

namespace
{

constexpr size_t kMinArpFrameLen = sizeof(snet::layers::ethernet_header) + sizeof(snet::layers::arp_header);

constexpr uint16_t kHwEthernet = 1;

} // namespace

ArpResolver::ArpResolver(IArpTransport& transport, std::chrono::milliseconds retry, int maxRetries)
    : transport_(transport)
    , retry_(retry)
    , maxRetries_(maxRetries)
{
}

void ArpResolver::addLocal(DeviceId iface, const IPv4Address& ip, const MacAddress& mac)
{
    local_[iface] = LocalEntry{ip, mac};
}

nonstd::optional<ArpResolver::MacAddress> ArpResolver::lookup(DeviceId iface, const IPv4Address& ip) const
{
    auto it = table_.find({iface, ip});
    if (it == table_.end() || !it->second.mac)
        return nonstd::nullopt;
    return it->second.mac;
}

void ArpResolver::observe(DeviceId iface, const IPv4Address& ip, const MacAddress& mac)
{
    auto& e = table_[{iface, ip}];
    e.mac = mac;
    e.nextProbe = Clock::time_point{};
    e.retries = 0;
}

void ArpResolver::request(DeviceId iface, const IPv4Address& ip)
{
    auto it = table_.find({iface, ip});
    if (it != table_.end() && it->second.mac)
        return;

    Key key{iface, ip};
    sendProbe(key);

    auto& e = table_[key];
    if (e.retries == 0)
        e.nextProbe = Clock::now() + retry_;
    e.retries++;
}

void ArpResolver::sendProbe(const Key& key)
{
    auto localIt = local_.find(key.iface);
    if (localIt == local_.end())
        return;

    transport_.sendRequest(key.iface, key.ip, localIt->second.mac, localIt->second.ip);
}

bool ArpResolver::handle(Packet* packet, DeviceId iface)
{
    auto* ethLayer = packet->findLayer(Ethernet);
    if (!ethLayer)
        return false;

    auto eth = packet->getHeader<EthernetHeader>(*ethLayer);
    if (eth.etherType() != EtherType::ARP)
        return false;

    auto* arpLayer = packet->findLayer(ARP);
    if (!arpLayer)
        return true;

    auto arp = packet->getHeader<ArpHeader>(*arpLayer);
    if (!arp.isValid())
        return true;

    if (arp.hardwareType() != kHwEthernet)
        return true;
    if (arp.protocolType() != static_cast<uint16_t>(EtherType::IP))
        return true;
    if (arp.hardwareLen() != 6 || arp.protocolLen() != 4)
        return true;

    MacAddress senderMac;
    std::memcpy(senderMac.data(), arp.senderHwAddr().data(), 6);

    const IPv4Address senderIp = IPv4Address::fromNetwork(arp.senderProtoAddr());
    const IPv4Address targetIp = IPv4Address::fromNetwork(arp.targetProtoAddr());

    switch (arp.operation())
    {
    case ArpOp::Request:
    {
        auto localIt = local_.find(iface);
        if (localIt != local_.end() && localIt->second.ip == targetIp)
        {
            observe(iface, senderIp, senderMac);

            transport_.sendReply(iface, senderMac, senderIp, localIt->second.mac, localIt->second.ip);
        }
        break;
    }
    case ArpOp::Reply:
    {
        auto it = table_.find({iface, senderIp});
        if (it != table_.end() && !it->second.mac)
            observe(iface, senderIp, senderMac);
        break;
    }
    default:
        break;
    }

    return true;
}

void ArpResolver::tick()
{
    const auto now = Clock::now();

    for (auto& [key, entry] : table_)
    {
        if (entry.mac)
            continue;
        if (now < entry.nextProbe)
            continue;
        if (entry.retries >= maxRetries_)
            continue;

        sendProbe(key);
        entry.nextProbe = now + retry_;
        entry.retries++;
    }
}

} // namespace snet::arp