#pragma once
#include <arpa/inet.h>

namespace snet::network
{
constexpr int invalid_socket = -1;
typedef int socket_type;
typedef sockaddr socket_addr_type;
typedef socklen_t socket_length_type;
typedef sockaddr_in sockaddr_in4_type;
typedef sockaddr_in6 sockaddr_in6_type;
typedef in_addr in_addr_type;
typedef in6_addr in6_addr_type;

} // namespace snet::network