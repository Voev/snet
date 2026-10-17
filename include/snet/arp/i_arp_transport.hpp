#pragma once
#include <snet/layers/l2/mac_address.hpp>
#include <snet/layers/l3/ip_address.hpp>
#include <snet/io/device.hpp>

namespace snet::arp
{

class IArpTransport
{
public:
    using DeviceId = snet::io::DeviceId;
    using MacAddress = snet::layers::MacAddress;
    using IPv4Address = snet::layers::IPv4Address;

    virtual ~IArpTransport() = default;

    virtual void sendRequest(DeviceId iface, const IPv4Address targetIp, const MacAddress& senderMac,
                             const IPv4Address& senderIp) = 0;

    virtual void sendReply(DeviceId iface, const MacAddress& dstMac, const IPv4Address& dstIp,
                           const MacAddress& senderMac, const IPv4Address& senderIp) = 0;
};

} // namespace snet::arp