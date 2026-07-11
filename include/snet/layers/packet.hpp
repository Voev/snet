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

class Packet final
{
public:
    Packet() = default;

    ~Packet() noexcept = default;

    Packet(const Packet& other) = delete;

    Packet& operator=(const Packet& other) = delete;

    Packet(Packet&& other) noexcept = default;

    Packet& operator=(Packet&& other) noexcept = default;

    inline void setRawData(const uint8_t* data, size_t len, LinkLayerType linkType = LINKTYPE_ETHERNET)
    {
        rawData_ = data;
        rawDataLen_ = len;
        linkLayerType_ = linkType;
        parse();
    }

    inline void setRawData(nonstd::span<const uint8_t> data, LinkLayerType linkType = LINKTYPE_ETHERNET)
    {
        setRawData(data.data(), data.size(), linkType);
    }

    inline size_t layerCount() const noexcept
    {
        return layerCount_;
    }

    inline const LayerInfo& getLayer(size_t index) const noexcept
    {
        return layers_[index];
    }

    inline const uint8_t* getPayloadData(const LayerInfo* layer) const noexcept
    {
        if (layer->payloadOffset > 0)
        {
            return rawData_ + layer->payloadOffset;
        }
        return nullptr;
    }

    inline size_t getPayloadSize(const LayerInfo* layer) const noexcept
    {
        if (layer->payloadOffset > 0)
        {
            return rawDataLen_ - layer->payloadOffset;
        }
        return 0;
    }

    inline nonstd::span<uint8_t> getPayload(const LayerInfo* layer) noexcept
    {
        if (layer && layer->payloadOffset > 0 && layer->payloadOffset < rawDataLen_)
        {
            return nonstd::span<uint8_t>(const_cast<uint8_t*>(rawData_ + layer->payloadOffset),
                                         rawDataLen_ - layer->payloadOffset);
        }
        return nonstd::span<uint8_t>();
    }

    nonstd::span<const uint8_t> getPayload(const LayerInfo* layer) const noexcept
    {
        if (layer && layer->payloadOffset > 0 && layer->payloadOffset < rawDataLen_)
        {
            return nonstd::span<const uint8_t>(rawData_ + layer->payloadOffset, rawDataLen_ - layer->payloadOffset);
        }
        return nonstd::span<const uint8_t>();
    }

    nonstd::span<const uint8_t> getPayload(ProtocolType protocol) const noexcept
    {
        auto* layer = findLayer(protocol);
        if (!layer)
        {
            return nonstd::span<const uint8_t>();
        }
        return getPayload(layer);
    }

    nonstd::span<uint8_t> getPayload(ProtocolType protocol) noexcept
    {
        auto* layer = findLayer(protocol);
        if (!layer)
        {
            return nonstd::span<uint8_t>();
        }
        return getPayload(layer);
    }

    nonstd::span<const uint8_t> getPayload(size_t layerIndex) const noexcept
    {
        if (layerIndex >= layerCount_)
        {
            return nonstd::span<const uint8_t>();
        }
        return getPayload(&layers_[layerIndex]);
    }

    nonstd::span<uint8_t> getPayload(size_t layerIndex) noexcept
    {
        if (layerIndex >= layerCount_)
        {
            return nonstd::span<uint8_t>();
        }
        return getPayload(&layers_[layerIndex]);
    }

    const LayerInfo* begin() const noexcept
    {
        return layers_.data();
    }

    const LayerInfo* end() const noexcept
    {
        return layers_.data() + layerCount_;
    }

    const LayerInfo* findLayer(ProtocolType protocol) const noexcept
    {
        for (size_t i = 0; i < layerCount_; ++i)
        {
            if (layers_[i].protocol == protocol)
            {
                return &layers_[i];
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
        if (layerIndex >= layerCount_)
        {
            return HeaderType();
        }
        return getHeader<HeaderType>(layers_[layerIndex]);
    }

    template <typename HeaderType>
    HeaderType getHeader(ProtocolType protocol) const noexcept
    {
        auto* layer = findLayer(protocol);
        if (!layer)
        {
            return HeaderType();
        }
        return getHeader<HeaderType>(*layer);
    }

    inline void clear() noexcept
    {
        rawData_ = nullptr;
        rawDataLen_ = 0;
        layerCount_ = 0;
    }

    inline void setTimestamp(Timestamp timestamp)
    {
        timestamp_ = std::move(timestamp);
    }

    inline Timestamp getTimestamp() const
    {
        return timestamp_;
    }

    inline const uint8_t* getData() const
    {
        return rawData_;
    }

    inline LinkLayerType getLinkLayerType() const
    {
        return linkLayerType_;
    }

    inline size_t getDataLen() const
    {
        return rawDataLen_;
    }

    static bool isLinkTypeValid(int linkTypeValue);

    void parse() noexcept;

private:
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

    nonstd::optional<LayerInfo> parseLayer(ProtocolType protocol, size_t globalOffset, size_t remaining) noexcept;

private:
    const uint8_t* rawData_{nullptr};
    size_t rawDataLen_{0UL};
    Timestamp timestamp_;
    std::array<LayerInfo, 8> layers_;
    size_t layerCount_ = 0;
    LinkLayerType linkLayerType_{LINKTYPE_ETHERNET};
};

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
            os << ip;
            break;
        }

        case TCP:
        {
            auto tcp = packet.getHeader<TCPHeader>(layer);
            os << tcp;
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