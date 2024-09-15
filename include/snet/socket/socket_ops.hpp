#pragma once
#include <system_error>
#include <snet/socket/types.hpp>

namespace snet::socket
{

SocketType socket(int domain, int socktype, int protocol, std::error_code& ec);

void close(SocketType sock);

SocketType connect(SocketType sock, const SocketAddrType* addr,
                   SocketLengthType addrlen, std::error_code& ec);

SocketType accept(SocketType sock, SocketAddrType* addr,
                  SocketLengthType* addrlen, std::error_code& ec);

int setSocketOption(SocketType s, int level, int optname, void* optval,
                    size_t* optlen, std::error_code& ec);

void setLinger(SocketType s, int onoff, int linger, std::error_code& ec);

int getSocketOption(SocketType s, int level, int optname, void* optval,
                    size_t* optlen, std::error_code& ec);

std::error_code getSocketError(SocketType s);

bool setNonBlocking(SocketType s, bool value, std::error_code& ec);

} // namespace snet::socket