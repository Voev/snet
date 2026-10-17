#pragma once

#include <snet/arp/i_arp_transport.hpp>
#include <snet/io/driver.hpp>

#include <snet/layers/in_memory_packet.hpp>
#include <snet/layers/packet_builder.hpp>
#include <snet/layers/link_type.hpp>
#include <snet/layers/l2/arp_header.hpp>
#include <snet/layers/l2/eth_header.hpp>

#include <casket/utils/endianness.hpp>
#include <casket/log/log.hpp>

namespace snet::arp
{

struct ArpTransportConfig
{
    size_t maxPacketSize{64};
    size_t packetHeadroom{0};
};

class ArpTransport final : public IArpTransport
{
public:
    explicit ArpTransport(io::Driver& driver, ArpTransportConfig config = {})
        : driver_(driver)
        , config_(std::move(config))
        , packet_(config_.maxPacketSize, config_.packetHeadroom)
    {
    }

    void sendRequest(DeviceId iface, const IPv4Address targetIp, const MacAddress& senderMac,
                     const IPv4Address& senderIp) override
    {
        buildAndSend(
            iface, MacAddress::broadcast(), senderMac, kOpRequest, senderMac, senderIp, MacAddress::zero(), targetIp);
    }

    void sendReply(DeviceId iface, const MacAddress& dstMac, const IPv4Address& dstIp, const MacAddress& senderMac,
                   const IPv4Address& senderIp) override
    {
        buildAndSend(iface, dstMac, senderMac, kOpReply, senderMac, senderIp, dstMac, dstIp);
    }

private:
    static constexpr uint16_t kEtherTypeArp = 0x0806;
    static constexpr uint16_t kHwEthernet = 1;
    static constexpr uint16_t kProtoIpv4 = 0x0800;
    static constexpr uint8_t kHwLen = 6;
    static constexpr uint8_t kProtoLen = 4;
    static constexpr uint16_t kOpRequest = 1;
    static constexpr uint16_t kOpReply = 2;

    void buildAndSend(DeviceId iface, const MacAddress& dstMac, const MacAddress& srcMac, uint16_t op,
                      const MacAddress& sha, const IPv4Address& spa, const MacAddress& tha, const IPv4Address& tpa)
    {
        using namespace snet::layers;

        PacketBuilder<InMemoryPacket> builder(&packet_);

        builder.eth()
            .set(&ethernet_header::dstMac, dstMac.bytes.data())
            .set(&ethernet_header::srcMac, srcMac.bytes.data())
            .set(&ethernet_header::etherType, casket::host_to_be(kEtherTypeArp))
            .build();

        builder.arp()
            .set(&arp_header::htype, casket::host_to_be(kHwEthernet))
            .set(&arp_header::ptype, casket::host_to_be(kProtoIpv4))
            .set(&arp_header::hlen, kHwLen)
            .set(&arp_header::plen, kProtoLen)
            .set(&arp_header::op, casket::host_to_be(op))
            .set(&arp_header::sha, sha.bytes.data())
            .set(&arp_header::spa, spa.toNetwork())
            .set(&arp_header::tha, tha.bytes.data())
            .set(&arp_header::tpa, tpa.toNetwork())
            .build();

        auto* built = builder.build(LINKTYPE_ETHERNET);
        if (!built)
        {
            CSK_LOG_ERROR("ArpTransport: build() failed");
            return;
        }

        driver_.transmitPacket(built->asPacket(), iface);
    }

    io::Driver& driver_;
    ArpTransportConfig config_;
    layers::InMemoryPacket packet_;
};

} // namespace snet::arp