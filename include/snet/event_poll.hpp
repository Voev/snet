#pragma once
#include <cstdint>
#include <cassert>
#include <unistd.h>
#include <sys/epoll.h>

class Epoll
{
  public:
    using Event = struct epoll_event;

    Epoll()
        : fd_(epoll_create1(0))
    {
    }

    ~Epoll()
    {
        close(fd_);
    }

    void Add(int fd, std::uint32_t events)
    {
        Control(EPOLL_CTL_ADD, fd, events);
    }

    void Add(void* ptr, int fd, std::uint32_t events)
    {
        Control(EPOLL_CTL_ADD, ptr, fd, events);
    }

    void Delete(int fd)
    {
        epoll_ctl(fd_, EPOLL_CTL_DEL, fd, nullptr);
    }

    void Modify(void* ptr, int fd, std::uint32_t events)
    {
        Control(EPOLL_CTL_MOD, ptr, fd, events);
    }

    void Modify(int fd, std::uint32_t events)
    {
        Control(EPOLL_CTL_MOD, fd, events);
    }

    void Control(int op, int fd, std::uint32_t events)
    {
        Event event = {0, 0};
        event.data.fd = fd;
        event.events = events;
        int r = epoll_ctl(fd_, op, fd, &event);
        assert(r != -1);
    }

    void Control(int op, void* ptr, int fd, std::uint32_t events)
    {
        Event event = {0, 0};
        event.data.ptr = ptr;
        event.events = events;
        epoll_ctl(fd_, op, fd, &event);
    }

    int Wait(Event* events, int maxCount, int timeout)
    {
        return epoll_wait(fd_, events, maxCount, timeout);
    }

  private:
    int fd_;
};
