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
    friend class Layer;

private:
    Timestamp timestamp_;

    uint8_t* m_RawData{nullptr};
    Layer* m_FirstLayer{nullptr};
    Layer* m_LastLayer{nullptr};

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

            // Проверка VLAN
            auto eth = EthernetHeader();
            if (!eth.initialize(info, *this))
            {
                return nonstd::nullopt;
            }

            if (eth.etherType() == 0x8100 || eth.etherType() == 0x88A8)
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
                return nonstd::nullopt;

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
            // TODO: пропуск extension headers
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

    // Range-based for поддержка
    const LayerInfo* begin() const noexcept
    {
        return m_Layers.data();
    }
    const LayerInfo* end() const noexcept
    {
        return m_Layers.data() + m_LayerCount;
    }

    // Получить первый слой определенного протокола
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

    // Удобные методы для получения заголовков
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

    virtual void insertData(int atIndex, const uint8_t* dataToInsert, size_t dataToInsertLen);

    virtual bool removeData(size_t atIndex, size_t numOfBytesToRemove);

    virtual bool reallocateData(size_t newBufferLength);

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

    void parsePacket(ProtocolTypeFamily parseUntil = UnknownProtocol,
                     OsiModelLayer parseUntilLayer = OsiModelLayerUnknown);

    /**
     * Get a pointer to the first (lowest) layer in the packet
     * @return A pointer to the first (lowest) layer in the packet
     */
    Layer* getFirstLayer() const
    {
        return m_FirstLayer;
    }

    /**
     * Get a pointer to the last (highest) layer in the packet
     * @return A pointer to the last (highest) layer in the packet
     */
    Layer* getLastLayer() const
    {
        return m_LastLayer;
    }

    /**
     * Get a pointer to the layer of a certain type (protocol). This method goes through the layers and returns a
     * layer that matches the give protocol type
     * @param[in] layerType The layer type (protocol) to fetch
     * @param[in] index If there are multiple layers of the same type, indicate which instance to fetch. The default
     * value is 0, meaning fetch the first layer of this type
     * @return A pointer to the layer or nullptr if no such layer was found
     */
    Layer* getLayerOfType(ProtocolType layerType, int index = 0) const;

    /**
     * A templated method to get a layer of a certain type (protocol). If no layer of such type is found, nullptr is
     * returned
     * @param[in] reverseOrder The optional parameter that indicates that the lookup should run in reverse order,
     * the default value is false
     * @return A pointer to the layer of the requested type, nullptr if not found
     */
    template <class TLayer>
    TLayer* getLayerOfType(bool reverseOrder = false) const;

    /**
     * A templated method to get the first layer of a certain type (protocol), start searching from a certain layer.
     * For example: if a packet looks like: EthLayer -> VlanLayer(1) -> VlanLayer(2) -> VlanLayer(3) -> IPv4Layer
     * and the user put VlanLayer(2) as a parameter and wishes to search for a VlanLayer, VlanLayer(3) will be
     * returned If no layer of such type is found, nullptr is returned
     * @param[in] startLayer A pointer to the layer to start search from
     * @return A pointer to the layer of the requested type, nullptr if not found
     */
    template <class TLayer>
    TLayer* getNextLayerOfType(Layer* startLayer) const;

    /**
     * A templated method to get the first layer of a certain type (protocol), start searching from a certain layer.
     * For example: if a packet looks like: EthLayer -> VlanLayer(1) -> VlanLayer(2) -> VlanLayer(3) -> IPv4Layer
     * and the user put VlanLayer(2) as a parameter and wishes to search for a VlanLayer, VlanLayer(1) will be
     * returned If no layer of such type is found, nullptr is returned
     * @param[in] startLayer A pointer to the layer to start search from
     * @return A pointer to the layer of the requested type, nullptr if not found
     */
    template <class TLayer>
    TLayer* getPrevLayerOfType(Layer* startLayer) const;

    /**
     * Check whether the packet contains a layer of a certain protocol
     * @param[in] protocolType The protocol type to search
     * @return True if the packet contains a layer of a certain protocol, false otherwise
     */
    bool isPacketOfType(ProtocolType protocolType) const;

    /**
     * Check whether the packet contains a layer of a certain protocol family
     * @param[in] protocolTypeFamily The protocol type family to search
     * @return True if the packet contains a layer of a certain protocol family, false otherwise
     */
    bool isPacketOfType(ProtocolTypeFamily protocolTypeFamily) const;

    /**
     * Each layer can have fields that can be calculate automatically from other fields using
     * Layer#computeCalculateFields(). This method forces all layers to calculate these fields values
     */
    void computeCalculateFields();

    /**
     * Each layer can print a string representation of the layer most important data using Layer#toString(). This
     * method aggregates this string from all layers and print it to a complete string containing all packet's
     * relevant data
     * @param[in] timeAsLocalTime Print time as local time or GMT. Default (true value) is local time, for GMT set
     * to false
     * @return A string containing most relevant data from all layers (looks like the packet description in
     * Wireshark)
     */
    std::string toString() const;

    /**
     * Similar to toString(), but instead of one string it outputs a list of strings, one string for every layer
     * @param[out] result A string vector that will contain all strings
     * @param[in] timeAsLocalTime Print time as local time or GMT. Default (true value) is local time, for GMT set
     * to false
     */
    void toStringList(std::vector<std::string>& result) const;

    static bool isLinkTypeValid(int linkTypeValue);

private:
    void destructPacketData();

    bool extendLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToExtend);
    bool shortenLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToShorten);

    void reallocateRawData(size_t newSize);

    std::string printPacketInfo() const;

    Layer* createFirstLayer(layers::LinkLayerType linkType);

}; // class Packet

// implementation of inline methods

template <class TLayer>
TLayer* Packet::getLayerOfType(bool reverse) const
{
    if (!reverse)
    {
        if (dynamic_cast<TLayer*>(getFirstLayer()) != nullptr)
            return dynamic_cast<TLayer*>(getFirstLayer());

        return getNextLayerOfType<TLayer>(getFirstLayer());
    }

    // lookup in reverse order
    if (dynamic_cast<TLayer*>(getLastLayer()) != nullptr)
        return dynamic_cast<TLayer*>(getLastLayer());

    return getPrevLayerOfType<TLayer>(getLastLayer());
}

template <class TLayer>
TLayer* Packet::getNextLayerOfType(Layer* curLayer) const
{
    if (curLayer == nullptr)
        return nullptr;

    curLayer = curLayer->getNextLayer();
    while ((curLayer != nullptr) && (dynamic_cast<TLayer*>(curLayer) == nullptr))
    {
        curLayer = curLayer->getNextLayer();
    }

    return dynamic_cast<TLayer*>(curLayer);
}

template <class TLayer>
TLayer* Packet::getPrevLayerOfType(Layer* curLayer) const
{
    if (curLayer == nullptr)
        return nullptr;

    curLayer = curLayer->getPrevLayer();
    while (curLayer != nullptr && dynamic_cast<TLayer*>(curLayer) == nullptr)
    {
        curLayer = curLayer->getPrevLayer();
    }

    return dynamic_cast<TLayer*>(curLayer);
}

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