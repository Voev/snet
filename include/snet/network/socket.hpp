#pragma once
#include <snet/network/socket_utils.hpp>
#include <snet/network/endpoint.hpp>
#include <snet/utils/error_code_exception.hpp>

namespace snet::network
{
// io_uring_socket_service
template <typename Protocol> class Socket
{
public:
    Socket()
        : sock_(invalid_socket)
    {}

    ~Socket() noexcept
    {
        close();
    }

    void open(const Protocol& protocol)
    {
        // check opened
        std::error_code ec;
        sock_ = MakeSocket(protocol.family(), protocol.type(), protocol.protocol(), ec);
        THROW_IF_ERROR(ec);

        //fcntl(sock_, F_SETFL, fcntl(sd, F_GETFL, 0) | O_NONBLOCK);
    }

    void close() noexcept
    {
        DestroySocket(sock_);
    }

    void connect(const Endpoint& peer, std::error_code& ec)
    {
        Connect(sock_, peer.data(), peer.size(), ec);
    }

    socket_type get() const
    {
        return sock_;
    }

private:
    socket_type sock_;
};

} // namespace snet::network