#pragma once
#include <system_error>
#include <thread>

#include <sched.h>
#include <pthread.h>

namespace snet::os
{

class CPUSet
{
public:
    CPUSet()
    {
        CPU_ZERO(&set_);
    }

    void set(long fromCPU, long currCPU)
    {
        while (fromCPU <= currCPU)
        {
            CPU_SET(fromCPU, &set_);
            ++fromCPU;
        }
    }

    void setThreadAffinity(std::thread::native_handle_type nativeHandle,
                           std::error_code& ec)
    {
        auto err = pthread_setaffinity_np(nativeHandle, sizeof(set_), &set_);
        if (err != 0)
        {
            ec = std::make_error_code(static_cast<std::errc>(err));
            return;
        }
    }

private:
    cpu_set_t set_;
};

} // namespace snet::os
