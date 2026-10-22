#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

#include <snet/io.hpp>
#include <snet/arp/arp_resolver.hpp>
#include <snet/layers/packet.hpp>
#include <snet/layers/packet_sink.hpp>
#include <snet/layers/in_memory_packet.hpp>
#include <snet/layers/l2/mac_address.hpp>
#include <snet/layers/l3/ip_address.hpp>

#include <casket/log/log.hpp>

namespace snet::layers
{

/// @brief L2 sink for generated packets produced by TcpTransmitHandler.
///
/// `TcpTransmitHandler` builds IP+TCP packets (LINKTYPE_RAW) and hands
/// them here. This class owns the L2 responsibility for that path:
///
///   1. Resolve egress device by destination IP (subnet table).
///   2. Resolve destination MAC via ARP.
///   3. Take source MAC from the egress device.
///   4. Write the Ethernet header into the packet's headroom.
///   5. Hand the resulting frame to the driver via transmitPacket().
///
/// Original RX packets that flow through the PacketPipeline are NOT
/// routed here — ForwardingStage handles those independently.
class NetworkSink : public IPacketSink
{
public:
    static constexpr size_t ETH_HEADER_LEN = 14;
    static constexpr uint16_t ETH_TYPE_IPv4 = 0x0800;

    /// @brief Subnet entry used for egress resolution.
    struct Subnet
    {
        io::DeviceId iface{io::kInvalidDevice};
        IPv4Address  network{};
        IPv4Address  netmask{};
    };

    NetworkSink(io::Driver& driver, arp::ArpResolver& arp)
        : driver_(driver), arp_(arp)
    {
    }

    NetworkSink(const NetworkSink&)            = delete;
    NetworkSink& operator=(const NetworkSink&) = delete;

    /// @brief Registers a subnet for egress resolution.
    void addSubnet(io::DeviceId iface, IPv4Address network, IPv4Address netmask)
    {
        subnets_.push_back(Subnet{iface, network, netmask});
    }

    /// @brief Transmits an IP packet (LINKTYPE_RAW) produced by TcpTransmitHandler.
    ///
    /// On success the packet view is rewritten to LINKTYPE_ETHERNET and
    /// handed to the driver. On failure (no egress, ARP not ready,
    /// driver error) the packet is left untouched and `false` is returned
    /// so the caller can retry on the next pump.
    bool transmit(Packet* packet) override
    {
        if (!packet)
            return false;

        auto* memPkt = InMemoryPacket::fromPacket(packet);
        if (!memPkt)
        {
            CSK_LOG_ERROR("NetworkSink: packet is not an InMemoryPacket");
            return false;
        }

        if (memPkt->headroom() < ETH_HEADER_LEN)
        {
            CSK_LOG_ERROR("NetworkSink: headroom too small (%zu < %zu)",
                          memPkt->headroom(), ETH_HEADER_LEN);
            return false;
        }

        auto* ipLayer = packet->findLayer(IPv4);
        if (!ipLayer)
        {
            CSK_LOG_WARNING("NetworkSink: no IPv4 layer");
            return false;
        }

        const auto ip = packet->getHeader<IPv4Header>(*ipLayer);
        if (!ip.isValid())
        {
            CSK_LOG_WARNING("NetworkSink: invalid IPv4 header");
            return false;
        }

        const IPv4Address dstIp(ip.dstAddr());

        // ── 1. Resolve egress by destination subnet ──
        const auto egress = findEgress(dstIp);
        if (egress == io::kInvalidDevice)
        {
            CSK_LOG_WARNING("NetworkSink: no egress for %s",
                            dstIp.toString().c_str());
            return false;
        }

        // ── 2. Resolve destination MAC via ARP ──
        const auto dstMac = arp_.lookup(egress, dstIp);
        if (!dstMac)
        {
            arp_.request(egress, dstIp);
            return false;   // caller will retry on next pump
        }

        // ── 3. Source MAC from the egress device ──
        auto* device = io::FindDeviceById(driver_, egress);
        if (!device)
        {
            CSK_LOG_ERROR("NetworkSink: device not found for iface=%u",
                          static_cast<unsigned>(egress));
            return false;
        }

        const auto& srcMac = device->mac();

        // ── 4. Write Ethernet header into the packet headroom ──
        uint8_t* eth = memPkt->getBufferStart();

        std::memcpy(eth,     dstMac->data(),  6);
        std::memcpy(eth + 6, srcMac.data(),   6);
        eth[12] = static_cast<uint8_t>(ETH_TYPE_IPv4 >> 8);
        eth[13] = static_cast<uint8_t>(ETH_TYPE_IPv4 & 0xFF);

        const size_t ipLen    = packet->getDataLen();
        const size_t frameLen = ETH_HEADER_LEN + ipLen;

        packet->setRawData(
            nonstd::span<const uint8_t>(eth, frameLen),
            LINKTYPE_ETHERNET);

        // ── 5. Hand the frame to the driver ──
        const auto status = driver_.transmitPacket(packet, egress);
        if (status != Status::Success)
        {
            CSK_LOG_WARNING("NetworkSink: transmitPacket failed for %s "
                            "(%zu bytes)",
                            dstIp.toString().c_str(), frameLen);
            return false;
        }

        return true;
    }

    /// @brief Resolves egress device by destination IP using the subnet table.
    io::DeviceId findEgress(const IPv4Address& dstIp) const
    {
        const uint32_t dstNet = dstIp.toNetwork();

        for (const auto& s : subnets_)
        {
            const uint32_t net     = s.network.toNetwork();
            const uint32_t netmask = s.netmask.toNetwork();

            if ((dstNet & netmask) == (net & netmask))
                return s.iface;
        }

        return io::kInvalidDevice;
    }

private:
    io::Driver&            driver_;
    arp::ArpResolver&      arp_;
    std::vector<Subnet>    subnets_;
};

} // namespace snet::layers