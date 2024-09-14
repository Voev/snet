#pragma once
#include <cstdint>
#include <sys/epoll.h>
#include <system_error>

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

class Epoll final
{
public:
    using Event = struct epoll_event;
    using EventMask = std::uint32_t;

    Epoll();

    ~Epoll() noexcept;

    void close() noexcept;

    void add(int fd, EventMask events, std::error_code& ec) noexcept;

    void add(int fd, EventMask events);

    void add(void* ptr, int fd, EventMask events, std::error_code& ec) noexcept;

    void add(void* ptr, int fd, EventMask events);

    void modify(void* ptr, int fd, EventMask events,
                std::error_code& ec) noexcept;

    void modify(void* ptr, int fd, EventMask events);

    void modify(int fd, EventMask events, std::error_code& ec) noexcept;

    void modify(int fd, EventMask events);

    void del(int fd, std::error_code& ec) noexcept;

    void del(int fd);

    void control(int op, int fd, EventMask events,
                 std::error_code& ec) noexcept;

    void control(int op, void* ptr, int fd, EventMask events,
                 std::error_code& ec) noexcept;

    int wait(Event* events, int maxCount, int timeout, std::error_code& ec);

private:
    int fd_;
};

} // namespace snet::event