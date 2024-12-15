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

int setSocketOption(SocketType s, int level, int optname, void* optval,
                    size_t optlen, std::error_code& ec)
{
    int ret = ::setsockopt(s, level, optname, optval,
                           static_cast<SocketLengthType>(optlen));
    if (ret == InvalidSocket)
    {
        ec = utils::GetLastSystemError();
    }
    return ret;
}

void setLinger(SocketType s, int onoff, int linger, std::error_code& ec)
{
    struct linger sl = {.l_onoff = onoff, .l_linger = linger};
    setSocketOption(s, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl), ec);
}

int getSocketOption(SocketType s, int level, int optname, void* optval,
                    size_t* optlen, std::error_code& ec)
{
    assert(optlen != nullptr);

    SocketLengthType tmp_optlen = static_cast<SocketLengthType>(*optlen);
    int ret = ::getsockopt(s, level, optname, optval, &tmp_optlen);
    if (ret == InvalidSocket)
    {
        ec = utils::GetLastSystemError();
    }
    if (optlen)
    {
        *optlen = static_cast<std::size_t>(tmp_optlen);
    }
    return ret;
}

std::error_code getSocketError(SocketType s)
{
    std::error_code ec;
    int sockType{};
    size_t sockTypeLen = sizeof(sockType);

    int ret =
        getSocketOption(s, SOL_SOCKET, SO_ERROR, &sockType, &sockTypeLen, ec);
    if (ret == InvalidSocket)
    {
        return ec;
    }
    return std::make_error_code(static_cast<std::errc>(ret));
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