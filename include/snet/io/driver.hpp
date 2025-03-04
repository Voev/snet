#pragma once
#include <memory>
#include <functional>
#include <snet/io/dynamic_library.hpp>
#include <snet/daq/daq.h>
#include <snet/io/driver_config.hpp>

namespace snet::io
{

class Driver
{
public:
    Driver() = default;

    virtual ~Driver() noexcept = default;

    virtual int start()
    {
        return DAQ_ERROR_NOTSUP;
    }

    virtual int stop()
    {
        return DAQ_ERROR_NOTSUP;
    }

    virtual int setFilter(const std::string& filter)
    {
        (void)filter;
        return DAQ_ERROR_NOTSUP;
    }

    virtual int inject(DAQ_MsgType type, const void* hdr, const uint8_t* data, uint32_t data_len)
    {
        (void)type;
        (void)hdr;
        (void)data;
        (void)data_len;
        return DAQ_ERROR_NOTSUP;
    }

    virtual int injectRelative(SNetIO_Message_t* msg, const uint8_t* data, uint32_t data_len,
                               int reverse)
    {
        (void)msg;
        (void)data;
        (void)data_len;
        (void)reverse;
        return DAQ_ERROR_NOTSUP;
    }

    virtual int interrupt()
    {
        return DAQ_ERROR_NOTSUP;
    }

    virtual int ioctl(DAQ_IoctlCmd cmd, void* arg, size_t arglen)
    {
        (void)cmd;
        (void)arg;
        (void)arglen;
        return DAQ_ERROR_NOTSUP;
    }

    virtual int getStats(DAQ_Stats_t* stats)
    {
        (void)stats;
        return DAQ_ERROR_NOTSUP;
    }

    virtual void resetStats()
    {
    }

    virtual int getSnaplen() const
    {
        return 0;
    }

    virtual uint32_t getType() const
    {
        return 0U;
    }

    virtual uint32_t getCapabilities() const
    {
        return 0U;
    }

    virtual int getDataLinkType() const
    {
        return 0;
    }

    virtual DAQ_RecvStatus receiveMsgs(SNetIO_Message_t* msgs[], const size_t maxSize,
                                       size_t* received)
    {
        (void)msgs;
        (void)maxSize;
        (void)received;
        return DAQ_RSTAT_ERROR;
    }

    virtual int finalizeMsg(const SNetIO_Message_t* msg, DAQ_Verdict verdict)
    {
        (void)msg;
        (void)verdict;
        return DAQ_ERROR_NOTSUP;
    }

    virtual int getMsgPoolInfo(DAQ_MsgPoolInfo_t* info)
    {
        (void)info;
        return DAQ_ERROR_NOTSUP;
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
