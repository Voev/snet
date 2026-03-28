#pragma once
#include <linux/netfilter.h>

#include <snet/layers/packet.hpp>
#include <casket/types/intrusive_list.hpp>

namespace snet::driver
{

struct NfqPacket final : public casket::IntrusiveListNode<NfqPacket>
{
    layers::Packet packet;
    const nlmsghdr* mh{nullptr};
    nfqnl_msg_packet_hdr* ph{nullptr};
    uint8_t* data{nullptr};

    static NfqPacket* fromPacket(layers::Packet* packet)
    {
        if (!packet)
            return nullptr;

        static const size_t offset = []() -> size_t
        {
            NfqPacket dummy;
            return reinterpret_cast<size_t>(&dummy.packet) - reinterpret_cast<size_t>(&dummy);
        }();

        return reinterpret_cast<NfqPacket*>(reinterpret_cast<char*>(packet) - offset);
    }
};

} // namespace snet::driver