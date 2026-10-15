#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>

#include <snet/io.hpp>

namespace snet
{

class ScopedFd
{
public:
    explicit ScopedFd(int fd) noexcept
        : fd_(fd)
    {
    }
    ~ScopedFd() noexcept
    {
        if (fd_ >= 0)
            ::close(fd_);
    }

    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;

    ScopedFd(ScopedFd&& other) noexcept
        : fd_(other.fd_)
    {
        other.fd_ = -1;
    }

    ScopedFd& operator=(ScopedFd&& other) noexcept
    {
        if (this != &other)
        {
            if (fd_ >= 0)
                ::close(fd_);
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    int get() const noexcept
    {
        return fd_;
    }
    bool valid() const noexcept
    {
        return fd_ >= 0;
    }

private:
    int fd_{-1};
};

layers::IPv4Address ifaceIpv4(snet::io::Driver& driver, snet::io::DeviceId id)
{
    auto* dev = FindDriverByDeviceId(driver, id);
    if (!dev)
        return {};

    ScopedFd fd(::socket(AF_INET, SOCK_DGRAM, 0));
    if (!fd.valid())
        return {};

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, dev->name().c_str(), IFNAMSIZ - 1);

    if (::ioctl(fd.get(), SIOCGIFADDR, &ifr) != 0)
        return {};

    auto* sin = reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr);
    return layers::IPv4Address(sin->sin_addr.s_addr);
}

} // namespace snet