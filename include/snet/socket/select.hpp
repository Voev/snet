#pragma once
#include <chrono>
#include <system_error>
#include <snet/socket/types.hpp>

namespace snet::socket
{

void WaitSocket(SocketType socket, bool read, std::chrono::seconds timeout, std::error_code& ec);

} // namespace snet::socket