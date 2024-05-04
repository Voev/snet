#pragma once
#include <cstdint>
#include <system_error>
#include <snet/network/types.hpp>

#include <sys/socket.h>

namespace snet::network
{

inline socket_type accept(socket_type sock, socket_addr_type* addr,
                          socket_length_type* addrlen, std::error_code& ec)
{
    if (sock == invalid_socket)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return invalid_socket;
    }

    socket_type ret = ::accept(sock, addr, addrlen);
    if (ret == invalid_socket)
    {
        ec = std::make_error_code(static_cast<std::errc>(errno));
    }

    return ret;
}

} // namespace snet::network