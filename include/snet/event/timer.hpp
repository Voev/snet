#pragma once
#include <signal.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <snet/event/context.hpp>
#include <snet/event/service.hpp>
#include <snet/utils/error_code.hpp>

namespace snet::event
{

static inline void msec2tspec(int msec, struct timespec* ts)
{
    if (msec)
    {
        ts->tv_sec = msec / 1000;
        ts->tv_nsec = (msec % 1000) * 1000000;
    }
    else
    {
        ts->tv_sec = 0;
        ts->tv_nsec = 0;
    }
}

class Timer final : public Service
{
public:
    explicit Timer(Context& ctx)
        : Service(ctx)
    {
    }

    ~Timer()
    {
        if (fd_ != -1)
        {
            close(fd_);
            fd_ = -1;
        }
    }

    int fd() const override { return fd_; }

    void set(int timeout, int period, std::error_code& ec)
    {
        fd_ = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (fd_ < 0)
            return;

        struct itimerspec time;
        msec2tspec(timeout, &time.it_value);
        msec2tspec(period, &time.it_interval);

        if (timerfd_settime(fd_, 0, &time, NULL) < 0)
            return;

        ctx().add(this, Read);
    }

private:
    int fd_;
    int timeout_;
    int period_;
};

} // namespace snet::event