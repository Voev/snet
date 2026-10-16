#pragma once
#include <snet/io/driver.hpp>

namespace snet::io
{

static inline Device* FindDeviceById(Driver& driver, const DeviceId id)
{
    auto deviceCount = driver.deviceCount();

    for (size_t i = 0; i < deviceCount; ++i)
    {
        auto* device = driver.deviceAt(i);
        if (device && device->id() == id)
        {
            return device;
        }
    }
    return nullptr;
}

}