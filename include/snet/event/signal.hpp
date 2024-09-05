#pragma once
#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <snet/event/context.hpp>
#include <snet/event/service.hpp>
#include <snet/utils/error_code.hpp>

namespace snet::event
{

class Signal final : public Service
{
public:
    explicit Signal(Context& ctx)
        : Service(ctx)
        , signo_(0)
    {
    }

    ~Signal()
    {
        if (fd_ != -1)
        {
            close(fd_);
            fd_ = -1;
        }
    }

    void set(int signalNumber, std::error_code& ec)
    {
        sigset_t mask{};

        int fd = signalfd(fd, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
        if (fd < 0)
        {
            ec = utils::GetLastSystemError();
            return;
        }

        sigemptyset(&mask);
        sigaddset(&mask, signalNumber);

        /* Block signals so that they aren't handled
           according to their default dispositions */
        if (sigprocmask(SIG_BLOCK, &mask, nullptr) == -1)
        {
            ec = utils::GetLastSystemError();
            return;
        }

        if (signalfd(fd, &mask, SFD_NONBLOCK) < 0)
        {
            ec = utils::GetLastSystemError();
            return;
        }

        fd_ = fd;
        signo_ = signalNumber;

        ctx().add(this, 0);
    }


private:
    int fd_;
    int signo_;
};

} // namespace snet::event