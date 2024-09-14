#pragma once
#include <arpa/inet.h>

namespace snet::socket
{

static constexpr int InvalidSocket = -1;
typedef int SocketType;
typedef sockaddr SocketAddrType;
typedef socklen_t SocketLengthType;
typedef sockaddr_in SockAddrIn4Type;
typedef sockaddr_in6 SockAddrIn6Type;

} // namespace snet::socket