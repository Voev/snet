#pragma once
#include <snet/io/raw_packet.hpp>
#include "forward_types.hpp"

namespace snet::driver
{

class NfqRawPacket final : public io::RawPacket
{
public:
    NfqRawPacket()
        : RawPacket(nullptr, 0, timeval{}, false)
    {}

    uint8_t* nlmsg_buf;
    const NlMessageHeader* mh;
    NlMessagePacketHeader* ph;
};

} // namespace snet::driver