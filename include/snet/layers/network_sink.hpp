#pragma once

#include <cstdint>
#include <cstring>
#include <iostream>

#include <snet/layers/packet.hpp>
#include <snet/layers/packet_sink.hpp>
#include <snet/layers/in_memory_packet.hpp>
#include <snet/layers/l2/mac_address.hpp>
#include <snet/layers/l3/ip_address.hpp>
#include <snet/io.hpp>
#include <snet/utils/print_hex.hpp>

#include <casket/log/log.hpp>

namespace snet::layers
{

class NetworkSink : public IPacketSink
{
public:
    static constexpr size_t ETH_HEADER_LEN = 14;
    static constexpr uint16_t ETH_TYPE_IPv4 = 0x0800;

    NetworkSink(snet::io::Driver* driver, const MacAddress& srcMac, const MacAddress& defaultDstMac = {})
        : driver_(driver)
        , srcMac_(srcMac)
        , defaultDstMac_(defaultDstMac)
    {
    }

    void setDefaultDstMac(const MacAddress& mac) noexcept
    {
        defaultDstMac_ = mac;
    }
    void setSrcMac(const MacAddress& mac) noexcept
    {
        srcMac_ = mac;
    }

    bool transmit(Packet* packet) override
    {
        if (!driver_ || !packet)
            return false;

        auto* memPkt = InMemoryPacket::fromPacket(packet);
        if (!memPkt)
        {
            CSK_LOG_ERROR("NetworkSink: packet is not InMemoryPacket "
                          "(cannot use headroom)");
            return false;
        }

        if (memPkt->headroom() < ETH_HEADER_LEN)
        {
            CSK_LOG_ERROR("NetworkSink: headroom too small (%zu < %zu)", memPkt->headroom(), ETH_HEADER_LEN);
            return false;
        }

        auto* ipLayer = packet->findLayer(IPv4);
        if (!ipLayer)
        {
            CSK_LOG_ERROR("NetworkSink: no IPv4 layer");
            return false;
        }

        auto ip = packet->getHeader<IPv4Header>(*ipLayer);
        if (!ip.isValid())
            return false;

        const IPAddress dstIP(ip.dstAddr());

        MacAddress dstMac = defaultDstMac_;
        if (dstMac.isZero())
        {
            CSK_LOG_WARNING("NetworkSink: no MAC for %s "
                            "(learner empty, no default)",
                            dstIP.toString().c_str());
            return false;
        }

        uint8_t* eth = memPkt->getBufferStart();

        std::memcpy(eth, dstMac.data(), 6);
        std::memcpy(eth + 6, srcMac_.data(), 6);
        eth[12] = static_cast<uint8_t>(ETH_TYPE_IPv4 >> 8);
        eth[13] = static_cast<uint8_t>(ETH_TYPE_IPv4 & 0xFF);

        const size_t ipLen = packet->getDataLen();
        const size_t frameLen = ETH_HEADER_LEN + ipLen;

        memPkt->asPacket()->setRawData(nonstd::span<const uint8_t>(eth, frameLen), LINKTYPE_ETHERNET);

        auto status = driver_->inject(eth, static_cast<uint32_t>(frameLen));
        if (status != Status::Success)
        {
            printf("[TX] inject failed: status=%d\n", static_cast<int>(status));
            return false;
        }
        return true;
    }

private:
    snet::io::Driver* driver_{nullptr};
    MacAddress srcMac_{};
    MacAddress defaultDstMac_{};
};

} // namespace snet::layers