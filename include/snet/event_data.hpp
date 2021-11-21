#pragma once
#include <memory>
#include <snet/socket.hpp>
#include <snet/ssl_handle.hpp>

class EventData
{
  public:
    EventData() = default;

    EventData(std::unique_ptr<Socket>&& sock, const SslContext& ctx)
        : sock_(std::move(sock))
        , sslSock_(std::make_unique<SslServerHandle>(ctx, *sock_.get()))
    {
    }

    Socket& GetSocket() const
    {
        return *(sock_.get());
    }

    SslServerHandle& GetSslSocket() const
    {
        return *(sslSock_.get());
    }

  private:
    std::unique_ptr<Socket> sock_{nullptr};
    std::unique_ptr<SslServerHandle> sslSock_{nullptr};
};
