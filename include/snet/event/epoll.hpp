#pragma once
#include <cstdint>
#include <cassert>
#include <unistd.h>
#include <sys/epoll.h>
#include <snet/utils/error_code.hpp>
#include <snet/utils/error_code_exception.hpp>

namespace snet::event
{

enum EventType
{
    Nothing = 0,
    Error = EPOLLERR,
    Read = EPOLLIN,
    Write = EPOLLOUT,
    PriorityMessage = EPOLLPRI,
    HangupEvent = EPOLLHUP,
    PeerShutdown = EPOLLRDHUP,
    OneShot = EPOLLONESHOT
};

class Epoll
{
public:
    using Event = struct epoll_event;
    using EventMask = std::uint32_t;

    Epoll()
        : fd_(epoll_create1(0))
    {
        if (fd_ < 0)
        {
            throw utils::ErrorCodeException(utils::GetLastSystemError());
        }
    }

    ~Epoll() noexcept
    {
        close();
    }

    inline void close() noexcept
    {
        if (fd_ == -1)
        {
            ::close(fd_);
            fd_ = -1;
        }
    }

    inline void add(int fd, EventMask events, std::error_code& ec) noexcept
    {
        control(EPOLL_CTL_ADD, fd, events, ec);
    }

    inline void add(int fd, EventMask events)
    {
        std::error_code ec;
        control(EPOLL_CTL_ADD, fd, events, ec);
        THROW_IF_ERROR(ec);
    }

    inline void add(void* ptr, int fd, EventMask events,
                    std::error_code& ec) noexcept
    {
        control(EPOLL_CTL_ADD, ptr, fd, events, ec);
    }

    inline void add(void* ptr, int fd, EventMask events)
    {
        std::error_code ec;
        control(EPOLL_CTL_ADD, ptr, fd, events, ec);
        THROW_IF_ERROR(ec);
    }

    inline void modify(void* ptr, int fd, EventMask events,
                       std::error_code& ec) noexcept
    {
        control(EPOLL_CTL_MOD, ptr, fd, events, ec);
    }

    inline void modify(void* ptr, int fd, EventMask events)
    {
        std::error_code ec;
        control(EPOLL_CTL_MOD, ptr, fd, events, ec);
        THROW_IF_ERROR(ec);
    }

    inline void modify(int fd, EventMask events,
                       std::error_code& ec) noexcept
    {
        control(EPOLL_CTL_MOD, fd, events, ec);
    }

    inline void modify(int fd, EventMask events)
    {
        std::error_code ec;
        control(EPOLL_CTL_MOD, fd, events, ec);
        THROW_IF_ERROR(ec);
    }

    inline void del(int fd, std::error_code& ec) noexcept
    {
        if (0 != epoll_ctl(fd_, EPOLL_CTL_DEL, fd, nullptr))
        {
            ec = utils::GetLastSystemError();
        }
    }

    inline void del(int fd)
    {
        std::error_code ec;
        del(fd, ec);
        THROW_IF_ERROR(ec);
    }

    inline void control(int op, int fd, EventMask events,
                        std::error_code& ec) noexcept
    {
        Event event = {0, 0};
        event.data.fd = fd;
        event.events = events;
        if (0 != epoll_ctl(fd_, op, fd, &event))
        {
            ec = utils::GetLastSystemError();
        }
    }

    inline void control(int op, void* ptr, int fd, EventMask events,
                        std::error_code& ec) noexcept
    {
        Event event = {0, 0};
        event.data.ptr = ptr;
        event.events = events;
        if (0 != epoll_ctl(fd_, op, fd, &event))
        {
            ec = utils::GetLastSystemError();
        }
    }

    inline int wait(Event* events, int maxCount, int timeout,
                    std::error_code& ec)
    {
        auto ret = epoll_wait(fd_, events, maxCount, timeout);
        if (ret < 0)
        {
            ec = utils::GetLastSystemError();
        }
        return ret;
    }

private:
    int fd_;
};

} // namespace snet::event