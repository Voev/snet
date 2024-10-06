
#pragma once

namespace snet::pcap
{

/**
 * @class IDevice
 * An abstract interface representing all packet processing devices. It stands
 * as the root class for all devices. This is an abstract class that cannot be
 * instantiated
 */
class IDevice
{
protected:
    bool deviceOpened_;

    // c'tor should not be public
    IDevice()
        : deviceOpened_(false)
    {
    }

public:
    virtual ~IDevice() = default;

    /**
     * Open the device
     * @return True if device was opened successfully, false otherwise
     */
    virtual bool open() = 0;

    /**
     * Close the device
     */
    virtual void close() noexcept = 0;

    /**
     * @return True if the file is opened, false otherwise
     */
    inline bool isOpened()
    {
        return deviceOpened_;
    }
};

} // namespace snet::pcap
