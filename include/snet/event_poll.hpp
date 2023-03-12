#pragma once
#include <cstdint>
#include <cassert>
#include <unistd.h>
#include <stdexcept>
#include <sys/epoll.h>

class Epoll
{
  public:
    using Event = struct epoll_event;

    Epoll()
        : fd_(epoll_create1(0))
    {
        if (fd_ < 0)
            throw std::runtime_error("can't create epoll");
    }

    ~Epoll()
    {
        close(fd_);
    }

    int Add(int fd, std::uint32_t events)
    {
        return Control(EPOLL_CTL_ADD, fd, events);
    }

    int Add(void* ptr, int fd, std::uint32_t events)
    {
        return Control(EPOLL_CTL_ADD, ptr, fd, events);
    }

    int Delete(int fd)
    {
        return epoll_ctl(fd_, EPOLL_CTL_DEL, fd, nullptr);
    }

    int Modify(void* ptr, int fd, std::uint32_t events)
    {
        return Control(EPOLL_CTL_MOD, ptr, fd, events);
    }

    int Modify(int fd, std::uint32_t events)
    {
        return Control(EPOLL_CTL_MOD, fd, events);
    }

    int Control(int op, int fd, std::uint32_t events)
    {
        Event event = {0, 0};
        event.data.fd = fd;
        event.events = events;
        return epoll_ctl(fd_, op, fd, &event);
    }

    int Control(int op, void* ptr, int fd, std::uint32_t events)
    {
        Event event = {0, 0};
        event.data.ptr = ptr;
        event.events = events;
        return epoll_ctl(fd_, op, fd, &event);
    }

    int Wait(Event* events, int maxCount, int timeout)
    {
        return epoll_wait(fd_, events, maxCount, timeout);
    }

  private:
    int fd_;
};
