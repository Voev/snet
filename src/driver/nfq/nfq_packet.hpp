#pragma once
#include <linux/netfilter.h>

#include <snet/layers/packet.hpp>
#include <casket/types/intrusive_list.hpp>

namespace snet::driver
{

/// @brief Netfilter queue packet wrapper with intrusive list support.
struct NfqPacket final : public casket::IntrusiveListNode<NfqPacket>
{
    layers::Packet packet;             ///< Base packet structure
    const nlmsghdr* mh{nullptr};       ///< Netlink message header
    nfqnl_msg_packet_hdr* ph{nullptr}; ///< Netfilter queue packet header
    uint8_t* data{nullptr};            ///< Raw packet data pointer

    /// @brief Converts a Packet pointer back to its containing NfqPacket.
    ///
    /// @param[in] packet Pointer to the embedded Packet structure.
    ///
    /// @return Pointer to the parent NfqPacket, or nullptr if input is nullptr.
    static NfqPacket* fromPacket(layers::Packet* packet)
    {
        if (!packet)
        {
            return nullptr;
        }

        static const size_t offset = []() -> size_t
        {
            NfqPacket dummy;
            return reinterpret_cast<size_t>(&dummy.packet) - reinterpret_cast<size_t>(&dummy);
        }();

        return reinterpret_cast<NfqPacket*>(reinterpret_cast<char*>(packet) - offset);
    }
};

} // namespace snet::driver