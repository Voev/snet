#pragma once
#include <cstdint>

#include <snet/layers/packet.hpp>
#include <casket/types/intrusive_list.hpp>

namespace snet::driver
{

/// @brief PCAP packet wrapper with intrusive list support.
struct PcapPacket final : public casket::IntrusiveListNode<PcapPacket>
{
    layers::Packet packet;   ///< Base packet.
    uint8_t* data{nullptr};  ///< Raw packet data.

    /// @brief Gets parent PcapPacket from embedded Packet pointer.
    ///
    /// @param[in] packet Embedded Packet pointer.
    ///
    /// @return Parent PcapPacket or nullptr.
    static PcapPacket* fromPacket(layers::Packet* packet)
    {
        if (!packet)
            return nullptr;

        static const size_t offset = []() -> size_t
        {
            PcapPacket dummy;
            return reinterpret_cast<size_t>(&dummy.packet) - reinterpret_cast<size_t>(&dummy);
        }();

        return reinterpret_cast<PcapPacket*>(reinterpret_cast<char*>(packet) - offset);
    }
};

} // namespace snet::driver