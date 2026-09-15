#pragma once
#include <cstdint>
#include <cstddef>
#include <snet/layers/packet.hpp>

namespace snet::layers
{

/// @brief Sink for outgoing raw packets.
class IPacketSink
{
public:
    virtual ~IPacketSink() = default;

    virtual bool transmit(Packet* packet) = 0;
};

} // namespace snet::layers