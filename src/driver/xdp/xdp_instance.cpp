#include "xdp_instance.hpp"
#include "xdp_driver.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <net/if_arp.h>

#include <casket/log/log.hpp>

namespace snet::driver
{

namespace
{

bool readMac(const std::string& iface, layers::MacAddress& macOut) noexcept
{
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return false;

    bool ok = false;
    if (::ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
    {
        std::memcpy(macOut.bytes.data(), ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        ok = true;
    }
    ::close(fd);
    return ok;
}

bool readMtu(const std::string& iface, uint32_t& mtuOut) noexcept
{
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return false;

    bool ok = false;
    if (::ioctl(fd, SIOCGIFMTU, &ifr) == 0)
    {
        mtuOut = static_cast<uint32_t>(ifr.ifr_mtu);
        ok = true;
    }
    ::close(fd);
    return ok;
}

} // namespace

XdpInstance::XdpInstance(XdpDriver& driver, io::DeviceId id)
    : driver_(driver)
    , id_(id)
{
}

XdpInstance::~XdpInstance() noexcept
{
    destroy();
}

bool XdpInstance::create(const std::string& iface, uint32_t queueId)
{
    name_ = iface;
    queueId_ = queueId;

    ifindex_ = ::if_nametoindex(iface.c_str());
    if (ifindex_ == 0)
    {
        driver_.logError("if_nametoindex(%s): %s", iface.c_str(), std::strerror(errno));
        return false;
    }

    if (!readMac(iface, mac_))
    {
        driver_.logError("read MAC(%s): %s", iface.c_str(), std::strerror(errno));
        return false;
    }

    if (!readMtu(iface, mtu_))
    {
        // Non-fatal: fall back to a sane default.
        mtu_ = 1500;
        driver_.logWarning("read MTU(%s) failed, using %u", iface.c_str(), mtu_);
    }

    snaplen_ = mtu_ + ETH_HLEN + 4; // ETH header + VLAN tag headroom
    return true;
}

bool XdpInstance::bindTo(struct xsk_umem* umem, const struct xsk_socket_config& cfg)
{
    if (::xsk_socket__create_shared(&xsk_, name_.c_str(), queueId_, umem, &rx_, &tx_, &fq_, &cq_, &cfg))
    {
        driver_.logError("xsk_socket__create_shared(%s, q=%u): %s",
                         name_.c_str(), queueId_, std::strerror(errno));
        return false;
    }

    fd_ = ::xsk_socket__fd(xsk_);
    if (fd_ < 0)
    {
        driver_.logError("xsk_socket__fd(%s, q=%u) returned %d", name_.c_str(), queueId_, fd_);
        return false;
    }
    return true;
}

void XdpInstance::destroy() noexcept
{
    if (xsk_)
    {
        ::xsk_socket__delete(xsk_);
        xsk_ = nullptr;
        fd_ = -1;
    }
    active_ = false;
}

// ---------------------------------------------------------------------------
// io::Device::send
// ---------------------------------------------------------------------------

bool XdpInstance::send(const uint8_t* data, size_t length) noexcept
{
    if (!data || length == 0)
        return false;
    if (!xsk_ || !active_)
        return false;

    const uint32_t len = static_cast<uint32_t>(length);

    if (len > driver_.frameSize() - driver_.headroom())
    {
        driver_.logWarning("send(%s, q=%u): frame too large (%u > %u)",
                           name_.c_str(), queueId_, len,
                           driver_.frameSize() - driver_.headroom());
        return false;
    }

    // Allocate a UMEM frame.
    uint64_t frameAddr = driver_.acquireFrame();
    if (frameAddr == UINT64_MAX)
    {
        // Try to reclaim completions and retry once.
        processCq(driver_.compSize());
        frameAddr = driver_.acquireFrame();
        if (frameAddr == UINT64_MAX)
            return false;
    }

    // Copy payload into the frame (past the headroom).
    uint8_t* dst = static_cast<uint8_t*>(driver_.umemBase())
                 + frameAddr
                 + driver_.headroom();
    std::memcpy(dst, data, len);

    // Hand off to the ring; if TX refuses, recycle the frame.
    if (!transmit(frameAddr, len))
    {
        driver_.releaseFrame(frameAddr);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Ring I/O
// ---------------------------------------------------------------------------

uint32_t XdpInstance::refillFq(uint32_t max)
{
    if (!xsk_ || max == 0)
        return 0;

    uint32_t produced = 0;

    while (produced < max)
    {
        const uint32_t availFrames = driver_.freeFrameCount();
        if (availFrames == 0)
            break;

        const uint32_t want = std::min(max - produced, availFrames);

        uint32_t idx = 0;
        const uint32_t space = ::xsk_ring_prod__reserve(&fq_, want, &idx);
        if (space == 0)
            break;

        uint32_t filled = 0;
        for (uint32_t i = 0; i < space; ++i)
        {
            uint64_t addr = driver_.acquireFrame();
            if (addr == UINT64_MAX)
                break;
            *::xsk_ring_prod__fill_addr(&fq_, idx + i) = addr;
            ++filled;
        }

        if (filled == 0)
            break;

        ::xsk_ring_prod__submit(&fq_, filled);
        produced += filled;

        if (filled < space)
            break;
    }

    return produced;
}

uint32_t XdpInstance::processCq(uint32_t max)
{
    if (!xsk_ || max == 0)
        return 0;

    uint32_t idx = 0;
    const uint32_t n = ::xsk_ring_cons__peek(&cq_, max, &idx);
    if (n == 0)
        return 0;

    for (uint32_t i = 0; i < n; ++i)
    {
        const uint64_t addr = *::xsk_ring_cons__comp_addr(&cq_, idx + i);
        driver_.releaseFrame(addr);
    }

    ::xsk_ring_cons__release(&cq_, n);
    return n;
}

bool XdpInstance::kickTx()
{
    if (!xsk_)
        return false;

    if (::xsk_ring_prod__needs_wakeup(&tx_))
    {
        if (::sendto(fd_, nullptr, 0, MSG_DONTWAIT, nullptr, 0) < 0)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK &&
                errno != ENETDOWN && errno != ENOBUFS)
            {
                driver_.logWarning("sendto(%s, q=%u) kick failed: %s",
                                   name_.c_str(), queueId_, std::strerror(errno));
                return false;
            }
        }
    }
    return true;
}

bool XdpInstance::transmit(uint64_t frameAddr, uint32_t len)
{
    if (!xsk_ || !active_)
        return false;

    uint32_t idx = 0;
    if (::xsk_ring_prod__reserve(&tx_, 1, &idx) != 1)
    {
        processCq(driver_.compSize());

        if (::xsk_ring_prod__reserve(&tx_, 1, &idx) != 1)
        {
            driver_.logWarning("XdpInstance: TX ring full on %s q=%u",
                               name_.c_str(), queueId_);
            return false;
        }
    }

    struct xdp_desc* d = ::xsk_ring_prod__tx_desc(&tx_, idx);
    d->addr = frameAddr;
    d->len = len;
    ::xsk_ring_prod__submit(&tx_, 1);

    return kickTx();
}

} // namespace snet::driver