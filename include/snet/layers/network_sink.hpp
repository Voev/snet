#pragma once

#include <cstdint>
#include <cstring>
#include <iostream>

#include <snet/layers/packet.hpp>
#include <snet/layers/packet_sink.hpp>
#include <snet/layers/in_memory_packet.hpp>
#include <snet/layers/l2/mac_address.hpp>
#include <snet/layers/l3/ip_address.hpp>
#include <snet/io.hpp>
#include <snet/utils/print_hex.hpp>

#include <casket/log/log.hpp>

namespace snet::layers
{

class NetworkSink : public IPacketSink
{
public:
    explicit NetworkSink(snet::io::Driver* driver)
        : driver_(driver) {}

    bool transmit(Packet* packet) override
    {
        if (!driver_ || !packet)
            return false;

        auto st = driver_->injectPacket(packet);
        return st == Status::Success;
    }

private:
    snet::io::Driver* driver_{nullptr};
};

} // namespace snet::layers