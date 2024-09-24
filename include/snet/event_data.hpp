#pragma once
#include <memory>
#include <snet/socket.hpp>
#include <snet/tls/settings.hpp>
#include <snet/tls/connection.hpp>

class EventData
{
  public:
    EventData() = default;

    EventData(std::unique_ptr<Socket>&& sock, const snet::tls::ServerSettings& ctx)
        : sock_(std::move(sock))
        , sslSock_(std::make_unique<snet::tls::Connection>(ctx))
    {
    }

    Socket& GetSocket() const
    {
        return *(sock_.get());
    }

    snet::tls::Connection& GetSslSocket() const
    {
        return *(sslSock_.get());
    }

  private:
    std::unique_ptr<Socket> sock_{nullptr};
    std::unique_ptr<snet::tls::Connection> sslSock_{nullptr};
};
