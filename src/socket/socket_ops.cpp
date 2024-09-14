#include <cassert>
#include <cstdint>
#include <system_error>

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <snet/socket/socket_ops.hpp>
#include <snet/utils/error_code.hpp>

namespace snet::socket
{

SocketType socket(int domain, int socktype, int protocol, std::error_code& ec)
{
    int sock{InvalidSocket};

    sock = ::socket(domain, socktype, protocol);
    if (sock == InvalidSocket)
    {
        ec = utils::GetLastSystemError();
    }

    return sock;
}

void close(SocketType sock)
{
    if (sock != InvalidSocket)
    {
        ::close(sock);
    }
}

SocketType connect(SocketType sock, const SocketAddrType* addr,
                   SocketLengthType addrlen, std::error_code& ec)
{
    if (sock == InvalidSocket)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return InvalidSocket;
    }

    SocketType ret = ::connect(sock, addr, addrlen);
    if (ret == InvalidSocket)
    {
        ec = utils::GetLastSystemError();
    }

    return ret;
}

SocketType accept(SocketType sock, SocketAddrType* addr,
                  SocketLengthType* addrlen, std::error_code& ec)
{
    if (sock == InvalidSocket)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return InvalidSocket;
    }

    SocketType ret = ::accept(sock, addr, addrlen);
    if (ret == InvalidSocket)
    {
        ec = utils::GetLastSystemError();
    }

    return ret;
}

int getSocketOption(SocketType s, int level, int optname, void* optval,
                    size_t* optlen, std::error_code& ec)
{
    assert(optlen != nullptr);

    SocketLengthType tmp_optlen = static_cast<SocketLengthType>(*optlen);
    int ret = ::getsockopt(s, level, optname, (char*)optval, &tmp_optlen);
    if (ret == InvalidSocket)
    {
        ec = utils::GetLastSystemError();
    }
    if (optlen)
    {
        *optlen = (std::size_t)tmp_optlen;
    }
    return ret;
}

bool setNonBlocking(SocketType s, bool value, std::error_code& ec)
{
    if (s == InvalidSocket)
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

} // namespace snet::socket