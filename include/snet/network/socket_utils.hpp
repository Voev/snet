#pragma once
#include <cstdint>
#include <system_error>
#include <fcntl.h>
#include <snet/network/types.hpp>
#include <snet/utils/error_code.hpp>
#include <sys/socket.h>

namespace snet::network
{

inline socket_type MakeSocket(int domain, int socktype, int protocol,
                              std::error_code& ec)
{
    int sock{invalid_socket};

    sock = socket(domain, socktype, protocol);
    if (sock == invalid_socket)
    {
        ec = utils::GetLastSystemError();
    }

    return sock;
}

inline void DestroySocket(socket_type sock)
{
    if (sock != invalid_socket)
    {
        close(sock);
    }
}

inline socket_type Connect(socket_type sock, const socket_addr_type* addr,
                           socket_length_type addrlen, std::error_code& ec)
{
    if (sock == invalid_socket)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return invalid_socket;
    }

    socket_type ret = ::connect(sock, addr, addrlen);
    if (ret == invalid_socket)
    {
        ec = utils::GetLastSystemError();
    }

    return ret;
}

inline socket_type Accept(socket_type sock, socket_addr_type* addr,
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
        ec = utils::GetLastSystemError();
    }

    return ret;
}

inline int GetSocketOption(socket_type s, int level, int optname, void* optval,
                           size_t* optlen, std::error_code& ec)
{
    socket_length_type tmp_optlen = (socket_length_type)*optlen;
    int ret = ::getsockopt(s, level, optname, (char*)optval, &tmp_optlen);
    if (ret == invalid_socket)
    {
        ec = utils::GetLastSystemError();
    }
    if (optlen)
    {
        *optlen = (std::size_t)tmp_optlen;
    }
    return ret;
}

inline bool SetNonBlocking(socket_type s, bool value, std::error_code& ec)
{
    if (s == invalid_socket)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return false;
    }

    int result = ::fcntl(s, F_GETFL, 0);
    if (result < 0)
    {
        ec = utils::GetLastSystemError();
        return false;
    }
    else
    {
        int flag = (value ? (result | O_NONBLOCK) : (result & ~O_NONBLOCK));
        result = ::fcntl(s, F_SETFL, flag);
        if (result < 0)
        {
            ec = utils::GetLastSystemError();
            return false;
        }
    }
    
    return true;
}

} // namespace snet::network
