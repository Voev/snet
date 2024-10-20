#pragma once
#include <snet/socket/types.hpp>
#include <snet/socket/socket_ops.hpp>
#include <snet/socket/endpoint.hpp>
#include <snet/utils/exception.hpp>

namespace snet::socket
{

class Socket
{
public:
    Socket()
        : sock_(InvalidSocket)
    {
    }

    ~Socket() noexcept
    {
        close();
    }

    template <typename Protocol> void open(const Protocol& protocol)
    {
        std::error_code ec;
        sock_ =
            socket(protocol.family(), protocol.type(), protocol.protocol(), ec);
        utils::ThrowIfError(ec);
    }

    void close() noexcept
    {
        if(sock_ != InvalidSocket)
        {
            socket::close(sock_);
            sock_ = InvalidSocket;
        }
    }

    void connect(const Endpoint& peer, std::error_code& ec) noexcept
    {
        socket::connect(sock_, peer.data(), peer.size(), ec);
    }

    void connect(const Endpoint& peer)
    {
        std::error_code ec;
        socket::connect(sock_, peer.data(), peer.size(), ec);
        utils::ThrowIfError(ec);
    }

    SocketType get() const
    {
        return sock_;
    }

private:
    SocketType sock_;
};

} // namespace snet::socket