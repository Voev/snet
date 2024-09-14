
#include <unistd.h> // close
#include <snet/event/epoll.hpp>
#include <snet/utils/error_code.hpp>
#include <snet/utils/error_code_exception.hpp>

namespace snet::event
{

Epoll::Epoll()
    : fd_(epoll_create1(0))
{
    if (fd_ < 0)
    {
        throw utils::ErrorCodeException(utils::GetLastSystemError());
    }
}

Epoll::~Epoll() noexcept
{
    close();
}

void Epoll::close() noexcept
{
    if (fd_ == -1)
    {
        ::close(fd_);
        fd_ = -1;
    }
}

void Epoll::add(int fd, EventMask events, std::error_code& ec) noexcept
{
    control(EPOLL_CTL_ADD, fd, events, ec);
}

void Epoll::add(int fd, EventMask events)
{
    std::error_code ec;
    control(EPOLL_CTL_ADD, fd, events, ec);
    THROW_IF_ERROR(ec);
}

void Epoll::add(void* ptr, int fd, EventMask events,
                std::error_code& ec) noexcept
{
    control(EPOLL_CTL_ADD, ptr, fd, events, ec);
}

void Epoll::add(void* ptr, int fd, EventMask events)
{
    std::error_code ec;
    control(EPOLL_CTL_ADD, ptr, fd, events, ec);
    THROW_IF_ERROR(ec);
}

void Epoll::modify(void* ptr, int fd, EventMask events,
                   std::error_code& ec) noexcept
{
    control(EPOLL_CTL_MOD, ptr, fd, events, ec);
}

void Epoll::modify(void* ptr, int fd, EventMask events)
{
    std::error_code ec;
    control(EPOLL_CTL_MOD, ptr, fd, events, ec);
    THROW_IF_ERROR(ec);
}

void Epoll::modify(int fd, EventMask events, std::error_code& ec) noexcept
{
    control(EPOLL_CTL_MOD, fd, events, ec);
}

void Epoll::modify(int fd, EventMask events)
{
    std::error_code ec;
    control(EPOLL_CTL_MOD, fd, events, ec);
    THROW_IF_ERROR(ec);
}

void Epoll::del(int fd, std::error_code& ec) noexcept
{
    if (0 != epoll_ctl(fd_, EPOLL_CTL_DEL, fd, nullptr))
    {
        ec = utils::GetLastSystemError();
    }
}

void Epoll::del(int fd)
{
    std::error_code ec;
    del(fd, ec);
    THROW_IF_ERROR(ec);
}

void Epoll::control(int op, int fd, EventMask events,
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

void Epoll::control(int op, void* ptr, int fd, EventMask events,
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

int Epoll::wait(Event* events, int maxCount, int timeout, std::error_code& ec)
{
    auto ret = epoll_wait(fd_, events, maxCount, timeout);
    if (ret < 0)
    {
        ec = utils::GetLastSystemError();
    }
    return ret;
}

} // namespace snet::event