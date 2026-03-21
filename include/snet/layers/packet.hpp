#pragma once

#include <stdint.h>
#include <sys/time.h>
#include <stddef.h>
#include <vector>
#include <unordered_map>
#include <casket/nonstd/span.hpp>
#include <casket/nonstd/optional.hpp>

#include <snet/layers/link_type.hpp>
#include <snet/layers/protocol.hpp>
#include <snet/layers/layer.hpp>
#include <snet/layers/timestamp.hpp>

#include <snet/layers/l2/eth_header.hpp>
#include <snet/layers/l3/ip_proto.hpp>
#include <snet/layers/l3/ipv4_header.hpp>
#include <snet/layers/l3/ip_address.hpp>
#include <snet/layers/l4/tcp_header.hpp>

namespace snet::layers
{

class Packet
{
private:
    Timestamp timestamp_;

    uint8_t* m_RawData{nullptr};

    std::array<LayerInfo, 8> m_Layers;
    size_t m_LayerCount = 0;

    size_t m_RawDataLen{0UL};
    size_t m_MaxPacketLen{0UL};
    size_t m_FrameLength{0UL};

    LinkLayerType m_LinkLayerType{LINKTYPE_ETHERNET};

    bool m_CanReallocateData{false};
    bool m_DeleteRawDataAtDestructor{false};

    static ProtocolType getProtocolFromLinkType(LinkLayerType linkType)
    {
        switch (linkType)
        {
        case LinkLayerType::LINKTYPE_ETHERNET:
            return Ethernet;
        default:
            return UnknownProtocol;
        }
    }

    ProtocolType getNextProtocol(const LayerInfo& layer) const noexcept
    {
        switch (layer.protocol)
        {
        case Ethernet:
            return getHeader<EthernetHeader>(layer).getNextProtocol();
        case IPv4:
            return getHeader<IPv4Header>(layer).getNextProtocol();
        case TCP:
        case UDP:
        default:
            return UnknownProtocol;
        }
    }

    nonstd::optional<LayerInfo> parseLayer(ProtocolType protocol, size_t globalOffset, size_t remaining) noexcept
    {
        LayerInfo info{};
        info.protocol = protocol;
        info.offset = globalOffset;
        info.payloadOffset = 0;

        switch (protocol)
        {
        case Ethernet:
        {
            constexpr size_t ETHERNET_LEN = 14;
            if (remaining < ETHERNET_LEN)
                return nonstd::nullopt;

            info.headerLength = ETHERNET_LEN;
            info.payloadOffset = globalOffset + ETHERNET_LEN;

            auto eth = EthernetHeader();
            if (!eth.initialize(info, *this))
            {
                return nonstd::nullopt;
            }

            if (eth.etherType() == EtherType::VLAN || eth.etherType() == EtherType::IEEE_802_1AD)
            {
                if (remaining >= ETHERNET_LEN + 4)
                {
                    info.headerLength = ETHERNET_LEN + 4;
                    info.payloadOffset = globalOffset + ETHERNET_LEN + 4;
                }
            }
            break;
        }

        case IPv4:
        {
            constexpr size_t MIN_IP_LEN = 20;
            if (remaining < MIN_IP_LEN)
                return nonstd::nullopt;

            auto ip = IPv4Header();
            if (!ip.initialize(info, *this))
            {
                return nonstd::nullopt;
            }

            info.headerLength = ip.headerLength();
            info.payloadOffset = globalOffset + info.headerLength;
            break;
        }

        case IPv6:
        {
            constexpr size_t IPV6_LEN = 40;
            if (remaining < IPV6_LEN)
                return nonstd::nullopt;

            info.headerLength = IPV6_LEN;
            info.payloadOffset = globalOffset + IPV6_LEN;
            break;
        }

        case TCP:
        {
            constexpr size_t MIN_TCP_LEN = 20;
            if (remaining < MIN_TCP_LEN)
                return nonstd::nullopt;

            TCPHeader tcp;
            if (!tcp.initialize(info, *this))
            {
                return nonstd::nullopt;
            }

            info.headerLength = tcp.headerLength();
            info.payloadOffset = globalOffset + info.headerLength;
            break;
        }

        default:
            info.headerLength = remaining;
            info.payloadOffset = globalOffset + remaining;
            break;
        }

        if (globalOffset + info.headerLength > m_RawDataLen)
        {
            return nonstd::nullopt;
        }

        return info;
    }

public:
    Packet();

    virtual ~Packet() noexcept;

    Packet(nonstd::span<const uint8_t> data, bool deleteRawDataAtDestructor,
           LinkLayerType layerType = LINKTYPE_ETHERNET);

    Packet(size_t maxPacketLen);

    Packet(nonstd::span<uint8_t> buffer);

    Packet(const Packet& other) = delete;

    Packet& operator=(const Packet& other) = delete;

    size_t layerCount() const noexcept
    {
        return m_LayerCount;
    }
    const LayerInfo& getLayer(size_t index) const noexcept
    {
        return m_Layers[index];
    }

    const uint8_t* getPayload(const LayerInfo* layer) const noexcept
    {
        if (layer->payloadOffset > 0)
        {
            return m_RawData + layer->payloadOffset;
        }
        return nullptr;
    }

    size_t getPayloadSize(const LayerInfo* layer) const noexcept
    {
        if (layer->payloadOffset > 0)
        {
            return m_RawDataLen - layer->payloadOffset;
        }
        return 0;
    }

    const LayerInfo* begin() const noexcept
    {
        return m_Layers.data();
    }

    const LayerInfo* end() const noexcept
    {
        return m_Layers.data() + m_LayerCount;
    }

    const LayerInfo* findLayer(ProtocolType protocol) const noexcept
    {
        for (size_t i = 0; i < m_LayerCount; ++i)
        {
            if (m_Layers[i].protocol == protocol)
            {
                return &m_Layers[i];
            }
        }
        return nullptr;
    }

    template <typename HeaderType>
    HeaderType getHeader(const LayerInfo& layer) const noexcept
    {
        HeaderType hdr;
        hdr.initialize(layer, *this);
        return hdr;
    }

    template <typename HeaderType>
    HeaderType getHeader(size_t layerIndex) const noexcept
    {
        if (layerIndex >= m_LayerCount)
            return HeaderType();
        return getHeader<HeaderType>(m_Layers[layerIndex]);
    }

    template <typename HeaderType>
    HeaderType getHeader(ProtocolType protocol) const noexcept
    {
        auto* layer = findLayer(protocol);
        if (!layer)
            return HeaderType();
        return getHeader<HeaderType>(*layer);
    }

    void parse() noexcept
    {
        m_LayerCount = 0;

        size_t packetLen = m_RawDataLen;
        size_t offset = 0;

        ProtocolType currentProto = getProtocolFromLinkType(m_LinkLayerType);

        while (offset < packetLen && m_LayerCount < 8)
        {
            size_t remaining = packetLen - offset;

            auto layerInfo = parseLayer(currentProto, offset, remaining);
            if (!layerInfo)
            {
                break;
            }

            m_Layers[m_LayerCount++] = *layerInfo;
            offset = layerInfo->getEndOffset();

            if (offset >= packetLen)
                break;

            const LayerInfo& currentLayer = m_Layers[m_LayerCount - 1];
            currentProto = getNextProtocol(currentLayer);

            if (currentProto == UnknownProtocol)
            {
                break;
            }
        }
    }

    void clear();

    virtual bool setRawData(nonstd::span<const uint8_t> data, LinkLayerType layerType, int frameLength);

    void setTimestamp(Timestamp timestamp)
    {
        timestamp_ = std::move(timestamp);
    }

    Timestamp getTimestamp() const
    {
        return timestamp_;
    }

    const uint8_t* getData() const
    {
        return m_RawData;
    }

    LinkLayerType getLinkLayerType() const
    {
        return m_LinkLayerType;
    }

    size_t getDataLen() const
    {
        return m_RawDataLen;
    }

    static bool isLinkTypeValid(int linkTypeValue);

private:
    void destructPacketData();

    void reallocateRawData(size_t newSize);

    std::string printPacketInfo() const;

}; // class Packet

} // namespace snet::layers

inline std::ostream& operator<<(std::ostream& os, const snet::layers::Packet& packet)
{
    using namespace snet::layers;

    if (packet.layerCount() == 0)
    {
        os << "Empty packet (no layers parsed)";
        return os;
    }

    os << "Packet (" << packet.getDataLen() << " bytes):\n";

    for (const auto& layer : packet)
    {
        os << "  [" << static_cast<int>(layer.protocol) << "] ";

        switch (layer.protocol)
        {
        case Ethernet:
        {
            auto eth = packet.getHeader<EthernetHeader>(layer);
            os << eth;
            break;
        }

        case IPv4:
        {
            auto ip = packet.getHeader<IPv4Header>(layer);
            if (ip)
            {
                os << "IPv4: " << ip.srcAddr() << " -> " << ip.dstAddr()
                   << " (proto=" << static_cast<int>(ip.protocol()) << ", ttl=" << static_cast<int>(ip.ttl())
                   << ", len=" << ip.totalLen() << ")";
            }
            break;
        }

        case TCP:
        {
            auto tcp = packet.getHeader<TCPHeader>(layer);
            if (tcp)
            {
                os << "TCP: " << tcp.srcPort() << " -> " << tcp.dstPort() << " (seq=" << tcp.seqNum()
                   << ", ack=" << tcp.ackNum() << ", flags=";
                if (tcp.isSYN())
                    os << "SYN ";
                if (tcp.isACK())
                    os << "ACK ";
                if (tcp.isFIN())
                    os << "FIN ";
                if (tcp.isRST())
                    os << "RST ";
                if (tcp.isPSH())
                    os << "PSH ";
                if (tcp.isURG())
                    os << "URG ";
                os << ")";

                if (tcp.optionsLength() > 0)
                {
                    os << " [options=" << tcp.optionsLength() << " bytes]";
                }
            }
            break;
        }

        default:
            os << "Unknown protocol: " << static_cast<int>(layer.protocol);
            break;
        }

        size_t payloadSize = packet.getDataLen() - layer.payloadOffset;
        os << " [payload=" << payloadSize << " bytes]\n";
    }

    return os;
}