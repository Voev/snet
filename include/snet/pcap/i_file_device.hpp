
#pragma once
#include <string>
#include <snet/pcap/i_pcap_device.hpp>

namespace snet::pcap
{

/**
 * @class IFileDevice
 * An abstract class (cannot be instantiated, has a private c'tor) which is the
 * parent class for all file devices
 */
class IFileDevice : public IPcapDevice
{
protected:
    explicit IFileDevice(const std::string& fileName)
        : IPcapDevice()
        , fileName_(fileName)
    {
    }

    ~IFileDevice() noexcept
    {
        IFileDevice::close();
    }

public:
    /**
     * @return The name of the file
     */
    std::string getFileName() const
    {
        return fileName_;
    }

    // override methods

    /**
     * Close the file
     */
    void close() noexcept override
    {
        if (descriptor_ != nullptr)
        {
            descriptor_ = nullptr;
        }
        deviceOpened_ = false;
    }

protected:
    std::string fileName_;
};

} // namespace snet::pcap
