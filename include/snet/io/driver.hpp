#pragma once
#include <memory>
#include <functional>
#include <string>

#include <snet/io/types.hpp>
#include <snet/io/dynamic_library.hpp>
#include <snet/io/driver_config.hpp>
#include <snet/io/raw_packet.hpp>

namespace snet::io
{

class Driver
{
public:
    Driver() = default;
    
    virtual ~Driver() noexcept = default;

    virtual const char* getName() const = 0;

    virtual Status configure(const Config& config) = 0;

    virtual Status start() = 0;

    virtual Status stop() = 0;

    virtual Status inject(const uint8_t* data, uint32_t data_len) = 0;

    virtual Status interrupt() = 0;

    virtual Status getStats(Stats* stats) = 0;

    virtual void resetStats() = 0;

    virtual int getSnaplen() const = 0;

    virtual io::LinkLayerType getDataLinkType() const = 0;

    virtual RecvStatus receivePacket(RawPacket** rawPacket) = 0;

    virtual Status finalizePacket(RawPacket* rawPacket, Verdict verdict) = 0;

    virtual Status getMsgPoolInfo(PacketPoolInfo* info) = 0;
};

using DriverCreator = std::shared_ptr<Driver>(const DriverConfig&);

} // namespace snet::io
