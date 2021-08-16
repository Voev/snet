#pragma once
#include <memory>
#include <snet/socket.hpp>
#include <snet/ssl_handle.hpp>

class EventData
{
  public:
    EventData() = default;

    EventData(std::unique_ptr<Socket>&& sock, bool bListen)
        : sock_(std::move(sock))
        , bListen_(bListen)
    {
    }

    Socket* GetSocket() const
    {
        return sock_.get();
    }

    bool IsListening() const
    {
        return bListen_;
    }

    std::uint32_t GetEvents() const noexcept
    {
        return events_;
    }

    void AddEvents(std::uint32_t events) noexcept
    {
        events_ |= events;
    }

    void RemoveEvents(std::uint32_t events) noexcept
    {
        events_ &= ~events;
    }

  private:
    std::unique_ptr<Socket> sock_{nullptr};
    std::uint32_t events_{0};
    bool bListen_{false};
};
