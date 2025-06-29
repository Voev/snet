#include <cassert>
#include <cstdint>
#include <system_error>

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <snet/socket/socket_ops.hpp>
#include <casket/utils/error_code.hpp>

using namespace casket;

namespace snet::socket
{

SocketType CreateSocket(int domain, int socktype, int protocol, std::error_code& ec)
{
    int sock{InvalidSocket};

    sock = ::socket(domain, socktype, protocol);
    if (sock == InvalidSocket)
    {
        ec = GetLastSystemError();
    }

    return sock;
}

void CloseSocket(SocketType sock)
{
    if (sock != InvalidSocket)
    {
        ::close(sock);
    }
}

SocketType Connect(SocketType sock, const SocketAddrType* addr, SocketLengthType addrlen,
                   std::error_code& ec)
{
    if (sock == InvalidSocket)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return InvalidSocket;
    }

    SocketType ret = ::connect(sock, addr, addrlen);
    if (ret == InvalidSocket)
    {
        ec = GetLastSystemError();
    }

    return ret;
}

SocketType Accept(SocketType sock, SocketAddrType* addr, SocketLengthType* addrlen,
                  std::error_code& ec)
{
    if (sock == InvalidSocket)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return InvalidSocket;
    }

    SocketType ret = ::accept(sock, addr, addrlen);
    if (ret == InvalidSocket)
    {
        ec = GetLastSystemError();
    }

    return ret;
}

int SetSocketOption(SocketType s, int level, int optname, void* optval, size_t optlen,
                    std::error_code& ec)
{
    int ret = ::setsockopt(s, level, optname, optval, static_cast<SocketLengthType>(optlen));
    if (ret == InvalidSocket)
    {
        ec = GetLastSystemError();
    }
    return ret;
}

void SetLinger(SocketType s, int onoff, int linger, std::error_code& ec)
{
    struct linger sl{};
    sl.l_onoff = onoff;
    sl.l_linger = linger;
    SetSocketOption(s, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl), ec);
}

int GetSocketOption(SocketType s, int level, int optname, void* optval, size_t* optlen,
                    std::error_code& ec)
{
    assert(optlen != nullptr);

    SocketLengthType tmp_optlen = static_cast<SocketLengthType>(*optlen);
    int ret = ::getsockopt(s, level, optname, optval, &tmp_optlen);
    if (ret == InvalidSocket)
    {
        ec = GetLastSystemError();
    }
    if (optlen)
    {
        *optlen = static_cast<std::size_t>(tmp_optlen);
    }
    return ret;
}

std::error_code GetSocketError(SocketType s)
{
    std::error_code ec;
    int sockType{};
    size_t sockTypeLen = sizeof(sockType);

    int ret = GetSocketOption(s, SOL_SOCKET, SO_ERROR, &sockType, &sockTypeLen, ec);
    if (ret == InvalidSocket)
    {
        return ec;
    }
    return std::make_error_code(static_cast<std::errc>(ret));
}

void SetNonBlocking(SocketType s, bool value, std::error_code& ec)
{
    if (s == InvalidSocket)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return;
    }

    int ret = ::fcntl(s, F_GETFL, 0);
    if (ret < 0)
    {
        ec = GetLastSystemError();
    }
    else
    {
        int flag = (value ? (ret | O_NONBLOCK) : (ret & ~O_NONBLOCK));
        ret = ::fcntl(s, F_SETFL, flag);
        if (ret < 0)
        {
            ec = GetLastSystemError();
        }
    }
}

} // namespace snet::socket