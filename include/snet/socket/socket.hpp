#pragma once
#include <snet/socket/types.hpp>
#include <snet/socket/socket_ops.hpp>
#include <snet/socket/endpoint.hpp>
#include <snet/utils/error_code_exception.hpp>

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
        THROW_IF_ERROR(ec);
    }

    void close() noexcept
    {
        socket::close(sock_);
    }

    void connect(const Endpoint& peer)
    {
        std::error_code ec;
        socket::connect(sock_, peer.data(), peer.size(), ec);
        THROW_IF_ERROR(ec);
    }

    SocketType get() const
    {
        return sock_;
    }

private:
    SocketType sock_;
};

} // namespace snet::socket