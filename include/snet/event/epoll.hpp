#pragma once
#include <cstdint>
#include <cassert>
#include <unistd.h>
#include <sys/epoll.h>
#include <snet/network/types.hpp>

namespace snet::event
{

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

    void add(int fd, std::uint32_t events)
    {
        control(EPOLL_CTL_ADD, fd, events);
    }

    void add(void* ptr, int fd, std::uint32_t events)
    {
        control(EPOLL_CTL_ADD, ptr, fd, events);
    }

    void del(int fd)
    {
        epoll_ctl(fd_, EPOLL_CTL_DEL, fd, nullptr);
    }

    void modify(void* ptr, int fd, std::uint32_t events)
    {
        control(EPOLL_CTL_MOD, ptr, fd, events);
    }

    void modify(int fd, std::uint32_t events)
    {
        control(EPOLL_CTL_MOD, fd, events);
    }

    void control(int op, int fd, std::uint32_t events)
    {
        Event event = {0, 0};
        event.data.fd = fd;
        event.events = events;
        epoll_ctl(fd_, op, fd, &event);
    }

    void control(int op, void* ptr, int fd, std::uint32_t events)
    {
        Event event = {0, 0};
        event.data.ptr = ptr;
        event.events = events;
        epoll_ctl(fd_, op, fd, &event);
    }

    int wait(Event* events, int maxCount, int timeout)
    {
        return epoll_wait(fd_, events, maxCount, timeout);
    }

private: 
    network::socket_type fd_;
};

} // namespace snet::event