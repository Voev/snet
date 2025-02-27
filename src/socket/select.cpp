#include <snet/socket/select.hpp>
#include <casket/utils/error_code.hpp>

namespace snet::socket
{

void WaitSocket(SocketType socket, bool read, std::chrono::seconds timeout, std::error_code& ec)
{
    fd_set confds;
    struct timeval tv;

    if (socket == InvalidSocket)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return;
    }

    FD_ZERO(&confds);
    FD_SET(socket, &confds);
    tv.tv_sec = static_cast<time_t>(timeout.count());
    tv.tv_usec = 0;

    int ret = select(socket + 1, read ? &confds : nullptr, read ? nullptr : &confds, nullptr, &tv);
    if (ret == 0)
    {
        ec = std::make_error_code(std::errc::timed_out);
    }
    else if (ret == -1)
    {
        ec = casket::utils::GetLastSystemError();
    }
}

} // namespace snet::socket