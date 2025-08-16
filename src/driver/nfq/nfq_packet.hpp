#pragma once
#include <linux/netfilter.h>
#include <snet/layers/packet.hpp>

namespace snet::driver
{

class NfqPacket final : public layers::Packet
{
public:
    NfqPacket()
        : layers::Packet(nullptr, 0, timeval{}, false)
    {
    }

    ~NfqPacket() noexcept
    {
        delete[] buffer;
    }

    uint8_t* buffer;
    const nlmsghdr* mh;
    nfqnl_msg_packet_hdr* ph;
};

} // namespace snet::driver