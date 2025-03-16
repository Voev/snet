#pragma once
#include <memory>
#include <functional>

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

    virtual Status start()
    {
        if (next_)
            return next_->start();
        return Status::NotSupported;
    }

    virtual Status stop()
    {
        if (next_)
            return next_->stop();
        return Status::NotSupported;
    }

    virtual Status setFilter(const std::string& filter)
    {
        if (next_)
            return next_->setFilter(filter);
        return Status::NotSupported;
    }

    virtual Status inject(const uint8_t* data, uint32_t data_len)
    {
        if (next_)
            return next_->inject(data, data_len);
        return Status::NotSupported;
    }

    virtual Status interrupt()
    {
        if (next_)
            return next_->interrupt();
        return Status::NotSupported;
    }

    virtual Status getStats(Stats* stats)
    {
        if (next_)
            return next_->getStats(stats);
        return Status::NotSupported;
    }

    virtual void resetStats()
    {
        if (next_)
            next_->resetStats();
    }

    virtual int getSnaplen() const
    {
        if (next_)
            return next_->getSnaplen();
        return 0;
    }

    virtual uint32_t getType() const
    {
        if (next_)
            return next_->getType();
        return 0U;
    }

    virtual uint32_t getCapabilities() const
    {
        if (next_)
            return next_->getCapabilities();
        return 0U;
    }

    virtual io::LinkLayerType getDataLinkType() const
    {
        if (next_)
            return next_->getDataLinkType();
        return io::LINKTYPE_NULL;
    }

    virtual RecvStatus receivePacket(RawPacket& rawPacket)
    {
        if (next_)
            return next_->receivePacket(rawPacket);
        return RecvStatus::Error;
    }

    virtual Status finalizePacket(const RawPacket& rawPacket, Verdict verdict)
    {
        if (next_)
            return next_->finalizePacket(rawPacket, verdict);
        return Status::NotSupported;
    }

    virtual Status getMsgPoolInfo(PacketPoolInfo* info)
    {
        if (next_)
            return next_->getMsgPoolInfo(info);
        return Status::NotSupported;
    }

    void setNext(std::shared_ptr<Driver> next)
    {
        next_ = next;
    }

protected:
    std::shared_ptr<Driver> next_{nullptr};
};

using DriverCreator = std::shared_ptr<Driver>(const DriverConfig&);

} // namespace snet::io
