#pragma once
#include <cstdint>
#include <snet/layers/protocol.hpp>

namespace snet::layers
{

/// @brief Represents information about a protocol layer in a packet.
/// 
/// Contains metadata about a specific protocol layer including its protocol type,
/// offset within the packet, header length, and payload offset.
struct LayerInfo
{
    ProtocolType protocol;      ///< Protocol type of this layer.
    uint32_t offset;            ///< Offset from the start of the packet to the beginning of the layer header.
    uint16_t headerLength;      ///< Length of the layer header in bytes.
    uint16_t payloadOffset;     ///< Offset from the start of the packet to the beginning of the layer payload.

    /// @brief Calculates the end offset of the layer header.
    /// @return Offset from the start of the packet to the end of the layer header.
    uint32_t getEndOffset() const noexcept
    {
        return offset + headerLength;
    }
};

} // namespace snet::layers
