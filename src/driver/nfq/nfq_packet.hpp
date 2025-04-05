#pragma once
#include <linux/netfilter.h>
#include <snet/io/raw_packet.hpp>

namespace snet::driver
{

class NfqRawPacket final : public io::RawPacket
{
public:
    NfqRawPacket()
        : RawPacket(nullptr, 0, timeval{}, false)
    {
    }

    ~NfqRawPacket() noexcept
    {
        delete[] buffer;
    }

    uint8_t* buffer;
    const nlmsghdr* mh;
    nfqnl_msg_packet_hdr* ph;
};

} // namespace snet::driver