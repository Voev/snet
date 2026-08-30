// snet/layers/packet.hpp
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

/// @brief Non-owning packet viewer that provides protocol parsing and layer access.
///
/// The Packet class is a lightweight non-owning view of raw packet data.
/// It parses protocol layers on demand and provides type-safe access to
/// headers and payloads through spans and template methods.
///
/// Key features:
/// - Zero-copy access to packet data.
/// - On-demand protocol layer parsing.
/// - Span-based payload access for safety and convenience.
/// - Template-based header retrieval with compile-time type safety.
/// - Support for Ethernet, IPv4, TCP, UDP, and other common protocols.
///
/// @note The class does not own the underlying data. The caller must ensure
///       the data buffer remains valid for the lifetime of the Packet instance.
/// @note Instances are movable but not copyable to prevent accidental aliasing.
///
/// @code
///   Packet pkt;
///   pkt.setRawData(data, len, LINKTYPE_ETHERNET);
///
///   auto* ip = pkt.getHeader<IPv4Header>(IPv4);
///   if (ip) {
///       auto payload = pkt.getPayload(IPv4);
///       // ... process payload ...
///   }
/// @endcode
class Packet final
{
public:
    /// @brief Default constructor. Creates an empty packet viewer.
    Packet() = default;

    /// @brief Default destructor. Does not free the referenced data.
    ~Packet() noexcept = default;

    /// @brief Deleted copy constructor. Packets cannot be copied.
    Packet(const Packet& other) = delete;

    /// @brief Deleted copy assignment operator. Packets cannot be copied.
    Packet& operator=(const Packet& other) = delete;

    /// @brief Default move constructor. Transfers the view state.
    Packet(Packet&& other) noexcept = default;

    /// @brief Default move assignment operator. Transfers the view state.
    Packet& operator=(Packet&& other) noexcept = default;

    /// @brief Sets the packet data and parses protocol layers.
    ///
    /// Replaces the current view with new data and triggers layer parsing.
    ///
    /// @param data Pointer to raw packet data.
    /// @param len Length of the data in bytes.
    /// @param linkType Link layer type (default: Ethernet).
    inline void setRawData(const uint8_t* data, size_t len, LinkLayerType linkType = LINKTYPE_ETHERNET)
    {
        rawData_ = data;
        rawDataLen_ = len;
        linkLayerType_ = linkType;
        parse();
    }

    /// @brief Sets the packet data from a span.
    ///
    /// @param data Span of raw packet data.
    /// @param linkType Link layer type (default: Ethernet).
    inline void setRawData(nonstd::span<const uint8_t> data, LinkLayerType linkType = LINKTYPE_ETHERNET)
    {
        setRawData(data.data(), data.size(), linkType);
    }

    /// @brief Returns the number of parsed protocol layers.
    ///
    /// @return Number of layers successfully parsed.
    /// @note Never throws exceptions.
    inline size_t layerCount() const noexcept
    {
        return layerCount_;
    }

    /// @brief Returns layer information at the specified index.
    ///
    /// @param index Layer index (0 to layerCount()-1).
    /// @return Reference to LayerInfo at the specified index.
    /// @pre index < layerCount()
    /// @note Never throws exceptions.
    inline const LayerInfo& getLayer(size_t index) const noexcept
    {
        return layers_[index];
    }

    /// @brief Returns a pointer to the payload data of a specific layer.
    ///
    /// @param layer Pointer to the LayerInfo describing the layer.
    /// @return Pointer to the payload data, or nullptr if not available.
    /// @note Never throws exceptions.
    inline const uint8_t* getPayloadData(const LayerInfo* layer) const noexcept
    {
        if (layer->payloadOffset > 0)
        {
            return rawData_ + layer->payloadOffset;
        }
        return nullptr;
    }

    /// @brief Returns the size of the payload data for a specific layer.
    ///
    /// @param layer Pointer to the LayerInfo describing the layer.
    /// @return Payload size in bytes, or 0 if not available.
    /// @note Never throws exceptions.
    inline size_t getPayloadSize(const LayerInfo* layer) const noexcept
    {
        if (layer->payloadOffset > 0)
        {
            return rawDataLen_ - layer->payloadOffset;
        }
        return 0;
    }

    /// @brief Returns the payload of a specific layer as a mutable span.
    ///
    /// Provides mutable access to the payload data for in-place modification.
    ///
    /// @param layer Pointer to the LayerInfo describing the layer.
    /// @return Mutable span of the payload data, or empty span if not available.
    /// @note Never throws exceptions.
    inline nonstd::span<uint8_t> getPayload(const LayerInfo* layer) noexcept
    {
        if (layer && layer->payloadOffset > 0 && layer->payloadOffset < rawDataLen_)
        {
            return nonstd::span<uint8_t>(const_cast<uint8_t*>(rawData_ + layer->payloadOffset),
                                         rawDataLen_ - layer->payloadOffset);
        }
        return nonstd::span<uint8_t>();
    }

    /// @brief Returns the payload of a specific layer as a const span.
    ///
    /// @param layer Pointer to the LayerInfo describing the layer.
    /// @return Const span of the payload data, or empty span if not available.
    /// @note Never throws exceptions.
    inline nonstd::span<const uint8_t> getPayload(const LayerInfo* layer) const noexcept
    {
        if (layer && layer->payloadOffset > 0 && layer->payloadOffset < rawDataLen_)
        {
            return nonstd::span<const uint8_t>(rawData_ + layer->payloadOffset, rawDataLen_ - layer->payloadOffset);
        }
        return nonstd::span<const uint8_t>();
    }

    /// @brief Returns the payload of a protocol layer as a const span.
    ///
    /// @param protocol Protocol type to locate.
    /// @return Const span of the payload data, or empty span if layer not found.
    /// @note Never throws exceptions.
    inline nonstd::span<const uint8_t> getPayload(ProtocolType protocol) const noexcept
    {
        auto* layer = findLayer(protocol);
        if (!layer)
        {
            return nonstd::span<const uint8_t>();
        }
        return getPayload(layer);
    }

    /// @brief Returns the payload of a protocol layer as a mutable span.
    ///
    /// @param protocol Protocol type to locate.
    /// @return Mutable span of the payload data, or empty span if layer not found.
    /// @note Never throws exceptions.
    inline nonstd::span<uint8_t> getPayload(ProtocolType protocol) noexcept
    {
        auto* layer = findLayer(protocol);
        if (!layer)
        {
            return nonstd::span<uint8_t>();
        }
        return getPayload(layer);
    }

    /// @brief Returns the payload of a layer by index as a const span.
    ///
    /// @param layerIndex Index of the layer.
    /// @return Const span of the payload data, or empty span if index is invalid.
    /// @note Never throws exceptions.
    inline nonstd::span<const uint8_t> getPayload(size_t layerIndex) const noexcept
    {
        if (layerIndex >= layerCount_)
        {
            return nonstd::span<const uint8_t>();
        }
        return getPayload(&layers_[layerIndex]);
    }

    /// @brief Returns the payload of a layer by index as a mutable span.
    ///
    /// @param layerIndex Index of the layer.
    /// @return Mutable span of the payload data, or empty span if index is invalid.
    /// @note Never throws exceptions.
    inline nonstd::span<uint8_t> getPayload(size_t layerIndex) noexcept
    {
        if (layerIndex >= layerCount_)
        {
            return nonstd::span<uint8_t>();
        }
        return getPayload(&layers_[layerIndex]);
    }

    /// @brief Returns an iterator to the first parsed layer.
    ///
    /// @return Pointer to the first LayerInfo in the array.
    /// @note Never throws exceptions.
    inline const LayerInfo* begin() const noexcept
    {
        return layers_.data();
    }

    /// @brief Returns an iterator to the end of parsed layers.
    ///
    /// @return Pointer to the past-the-end LayerInfo.
    /// @note Never throws exceptions.
    inline const LayerInfo* end() const noexcept
    {
        return layers_.data() + layerCount_;
    }

    /// @brief Finds a layer by protocol type.
    ///
    /// @param protocol Protocol type to locate.
    /// @return Pointer to LayerInfo if found, nullptr otherwise.
    /// @note Never throws exceptions.
    inline const LayerInfo* findLayer(ProtocolType protocol) const noexcept
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

    /// @brief Retrieves a header from a specific layer.
    ///
    /// @tparam HeaderType The header type to retrieve (e.g., IPv4Header, TCPHeader).
    /// @param layer Reference to the LayerInfo describing the layer.
    /// @return The header object.
    /// @note Never throws exceptions.
    template <typename HeaderType>
    HeaderType getHeader(const LayerInfo& layer) const noexcept
    {
        HeaderType hdr;
        hdr.initialize(layer, *this);
        return hdr;
    }

    /// @brief Retrieves a header by layer index.
    ///
    /// @tparam HeaderType The header type to retrieve.
    /// @param layerIndex Index of the layer.
    /// @return The header object, or default if index is invalid.
    /// @note Never throws exceptions.
    template <typename HeaderType>
    HeaderType getHeader(size_t layerIndex) const noexcept
    {
        if (layerIndex >= layerCount_)
        {
            return HeaderType();
        }
        return getHeader<HeaderType>(layers_[layerIndex]);
    }

    /// @brief Retrieves a header by protocol type.
    ///
    /// @tparam HeaderType The header type to retrieve.
    /// @param protocol Protocol type to locate.
    /// @return The header object, or default if protocol not found.
    /// @note Never throws exceptions.
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

    /// @brief Clears the packet view and resets all internal state.
    ///
    /// After calling clear(), the packet is empty and all layer information is lost.
    /// The raw data pointer is set to nullptr and length to zero.
    ///
    /// @note Never throws exceptions.
    inline void clear() noexcept
    {
        rawData_ = nullptr;
        rawDataLen_ = 0;
        timestamp_ = Timestamp();
        layerCount_ = 0;
    }

    /// @brief Sets the packet timestamp.
    ///
    /// @param timestamp The timestamp to assign to the packet.
    inline void setTimestamp(Timestamp timestamp)
    {
        timestamp_ = std::move(timestamp);
    }

    /// @brief Returns the packet timestamp.
    ///
    /// @return The timestamp associated with the packet.
    inline Timestamp getTimestamp() const
    {
        return timestamp_;
    }

    /// @brief Returns a pointer to the raw packet data.
    ///
    /// @return Pointer to the raw data, or nullptr if no data is set.
    /// @note Never throws exceptions.
    inline const uint8_t* getData() const
    {
        return rawData_;
    }

    /// @brief Returns the link layer type of the packet.
    ///
    /// @return LinkLayerType enumeration value.
    /// @note Never throws exceptions.
    inline LinkLayerType getLinkLayerType() const
    {
        return linkLayerType_;
    }

    /// @brief Returns the length of the packet data in bytes.
    ///
    /// @return Data length in bytes.
    /// @note Never throws exceptions.
    inline size_t getDataLen() const
    {
        return rawDataLen_;
    }

    /// @brief Checks if a given link type value is valid.
    ///
    /// @param linkTypeValue The link type value to check.
    /// @return true if the link type is supported, false otherwise.
    static bool isLinkTypeValid(int linkTypeValue);

    /// @brief Parses the packet layers from the attached raw data.
    ///
    /// This method is called automatically by setRawData(). It can also be called
    /// manually after modifying the packet data to re-parse the layers.
    ///
    /// @note Never throws exceptions.
    void parse() noexcept;

private:
    /// @brief Returns the protocol type from the link layer type.
    ///
    /// @param linkType Link layer type.
    /// @return Protocol type for the given link layer.
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

    /// @brief Returns the next protocol type after a given layer.
    ///
    /// @param layer The current layer information.
    /// @return Protocol type of the next layer, or UnknownProtocol.
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

    /// @brief Parses a single protocol layer from the raw data.
    ///
    /// @param protocol Protocol type to parse.
    /// @param globalOffset Offset from the start of the packet.
    /// @param remaining Remaining bytes in the packet.
    /// @return LayerInfo if parsing succeeded, nullopt otherwise.
    nonstd::optional<LayerInfo> parseLayer(ProtocolType protocol, size_t globalOffset, size_t remaining) noexcept;

private:
    const uint8_t* rawData_{nullptr};          ///< Pointer to raw packet data.
    size_t rawDataLen_{0UL};                   ///< Length of raw packet data in bytes.
    Timestamp timestamp_;                      ///< Packet timestamp.
    std::array<LayerInfo, 8> layers_;          ///< Array of parsed layers (max 8).
    size_t layerCount_ = 0;                    ///< Number of parsed layers.
    LinkLayerType linkLayerType_{LINKTYPE_ETHERNET}; ///< Link layer type.
};

} // namespace snet::layers

/// @brief Stream output operator for Packet.
///
/// @param os Output stream.
/// @param packet Packet to output.
/// @return Reference to the output stream.
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