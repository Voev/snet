#pragma once
#include <snet/io/driver.hpp>

namespace snet::io
{

class DriverGuard final
{
public:
    DriverGuard(Driver* driver)
        : driver_(driver)
    {
    }

    ~DriverGuard() noexcept
    {
        close();
    }

    void close() noexcept
    {
        if (driver_ && !closed_)
        {
            (void)driver_->interrupt();
            (void)driver_->stop();
        }
    }

    void interrupt() noexcept
    {
        if (driver_)
        {
            (void)driver_->interrupt();
        }
    }

private:
    Driver* driver_{nullptr};
    bool closed_{false};
};

} // namespace snet::io