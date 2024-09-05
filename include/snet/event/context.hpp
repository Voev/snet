#pragma once
#include <array>
#include <list>
#include <map>
#include <memory>
#include <cstdint>
#include <snet/event/epoll.hpp>
#include <snet/event/service.hpp>

namespace snet::event
{

class Service;

class Context
{
public:
    static constexpr int kMaxEvents = 32;
    using EpollEventArray = std::array<Epoll::Event, kMaxEvents>;

    Context(std::uint32_t maxEvents = kMaxEvents)
        : epoll_()
        , maxEvents_(maxEvents)
        , running_(false)
    {
    }

    void run()
    {
        int timeout = -1;
        int n;
        running_ = true;

        std::error_code ec;
        EpollEventArray ev;

        // libio

        while (running_)
        {
            n = epoll_.wait(ev.data(), maxEvents_, timeout, ec);

            if (n < 0)
            {
                if (static_cast<std::errc>(ec.value()) ==
                        std::errc::bad_file_descriptor ||
                    static_cast<std::errc>(ec.value()) ==
                        std::errc::invalid_argument)
                {
                    break;
                }

                continue;
            }

            if (n > 0)
            {
                for (int i = 0; i < n; ++i) {

                    auto data = static_cast<Service*>(ev[i].data.ptr);
                    auto events = ev[i].events;

                    data->callHandler(*data, events);
                }
            }
        }
    }

    void stop()
    {
        running_ = false;
    }

    void add(Service* service, uint32_t events)
    {
        if(service)
            epoll_.add(service, service->fd(), events);
    }

    void remove(Service* service)
    {
        if(service)
            epoll_.del(service->fd());
    }

private:
    Epoll epoll_;
    std::uint32_t maxEvents_;
    bool running_;
};

} // namespace snet::event