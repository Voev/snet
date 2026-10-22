#include <snet/arp/arp_resolver.hpp>

#include <snet/layers/l2/eth_header.hpp>
#include <snet/layers/l2/arp_header.hpp>

#include <casket/utils/endianness.hpp>
#include <casket/log/log.hpp>

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
    {
        CSK_LOG_DEBUG("ArpResolver: no Ethernet");
        return false;
    }

    auto eth = packet->getHeader<EthernetHeader>(*ethLayer);
    if (eth.etherType() != EtherType::ARP)
        return false;

    auto* arpLayer = packet->findLayer(ARP);
    if (!arpLayer)
    {
        CSK_LOG_DEBUG("ArpResolver: no ARP layer");
        return true;
    }

    auto arp = packet->getHeader<ArpHeader>(*arpLayer);
    if (!arp.isValid())
        return true;

    MacAddress senderMac;
    std::memcpy(senderMac.data(), arp.senderHwAddr().data(), 6);
    const IPv4Address senderIp = IPv4Address::fromNetwork(arp.senderProtoAddr());
    const IPv4Address targetIp = IPv4Address::fromNetwork(arp.targetProtoAddr());

    CSK_LOG_INFO("ARP: iface=%u op=%u spa=%s tpa=%s",
                 iface,
                 arp.operation(),
                 senderIp.toString().c_str(),
                 targetIp.toString().c_str());

    switch (arp.operation())
    {
    case ArpOp::Request:
    {
        auto localIt = local_.find(iface);
        CSK_LOG_INFO("ARP: local_.find(%u) → %s, ip=%s",
                     iface,
                     localIt != local_.end() ? "found" : "NOT FOUND",
                     localIt != local_.end() ? localIt->second.ip.toString().c_str() : "(none)");

        if (localIt != local_.end() && localIt->second.ip == targetIp)
        {
            CSK_LOG_INFO("ARP: sendReply to %s (mac=%02x:...)", senderIp.toString().c_str(), senderMac.data()[0]);
            observe(iface, senderIp, senderMac);
            transport_.sendReply(iface, senderMac, senderIp, localIt->second.mac, localIt->second.ip);
        }
        break;
    }
    case ArpOp::Reply:
    {
        auto it = table_.find({iface, senderIp});
        CSK_LOG_INFO("ARP reply: iface=%u spa=%s found=%d mac_set=%d",
                     iface,
                     senderIp.toString().c_str(),
                     it != table_.end(),
                     it != table_.end() && it->second.mac.has_value());

        if (it != table_.end() && !it->second.mac)
        {
            CSK_LOG_INFO("ARP reply: observe %s", senderIp.toString().c_str());
            observe(iface, senderIp, senderMac);
        }
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