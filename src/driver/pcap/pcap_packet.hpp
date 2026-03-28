#pragma once
#include <cstdint>

#include <snet/layers/packet.hpp>
#include <casket/types/intrusive_list.hpp>

namespace snet::driver
{

struct PcapPacket final : public casket::IntrusiveListNode<PcapPacket>
{
    layers::Packet packet;
    uint8_t* data{nullptr};

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