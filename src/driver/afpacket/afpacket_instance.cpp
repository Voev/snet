#include "afpacket_instance.hpp"
#include "afpacket_driver.hpp"

#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <net/if_arp.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include <unistd.h>

namespace snet::driver
{

Instance::Instance(AFPacketDriver& driver)
    : driver_(driver)
{}

Instance::~Instance() noexcept
{
    destroy();
}

bool Instance::create(const std::string& name)
{
    name_ = name;
    buffer_ = MAP_FAILED;

    fd_ = ::socket(PF_PACKET, SOCK_RAW, 0);
    if (fd_ == -1)
    {
        driver_.logError("could not open PF_PACKET socket for %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }

    int on = 1;
    if (::setsockopt(fd_, SOL_PACKET, PACKET_IGNORE_OUTGOING, &on, sizeof(on)) < 0)
    {
        // На старых ядрах (< 4.20) этой опции нет — не критично
        driver_.logWarning("PACKET_IGNORE_OUTGOING not supported: %s", std::strerror(errno));
        // не возвращаем false — продолжаем работу
    }
    else
    {
        driver_.logInfo("PACKET_IGNORE_OUTGOING enabled on %s", name.c_str());
    }

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, name_.c_str(), sizeof(ifr.ifr_name) - 1);
    if (::ioctl(fd_, SIOCGIFINDEX, &ifr) == -1)
    {
        driver_.logError("could not find index for device %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }
    index_ = static_cast<uint32_t>(ifr.ifr_ifindex);

    int val = TPACKET_V2;
    socklen_t len = sizeof(val);
    if (::getsockopt(fd_, SOL_PACKET, PACKET_HDRLEN, &val, &len) < 0)
    {
        driver_.logError("couldn't retrieve TPACKET_V2 header length on %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }
    tpHdrlen_ = static_cast<uint32_t>(val);

    val = TPACKET_V2;
    if (::setsockopt(fd_, SOL_PACKET, PACKET_VERSION, &val, sizeof(val)) < 0)
    {
        driver_.logError("couldn't activate TPACKET_V2 on %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }

    val = static_cast<int>(kVlanTagLen);
    if (::setsockopt(fd_, SOL_PACKET, PACKET_RESERVE, &val, sizeof(val)) < 0)
    {
        driver_.logError("couldn't set up %d-byte reservation on %s: %s", val, name_.c_str(), std::strerror(errno));
        return false;
    }

    val = 1;
    if (::setsockopt(fd_, SOL_PACKET, PACKET_QDISC_BYPASS, &val, sizeof(val)) < 0)
    {
        driver_.logError("couldn't configure qdisc bypass on %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }
    if (::setsockopt(fd_, SOL_PACKET, PACKET_LOSS, &val, sizeof(val)) < 0)
    {
        driver_.logError("couldn't configure PACKET_LOSS on %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }

    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, name_.c_str(), sizeof(ifr.ifr_name) - 1);
    if (::ioctl(fd_, SIOCGIFMTU, &ifr) == -1)
    {
        driver_.logError("could not query MTU for '%s': %s", name_.c_str(), std::strerror(errno));
        return false;
    }
    mtu_ = ifr.ifr_mtu;

    if (::getsockopt(fd_, SOL_PACKET, PACKET_RESERVE, &val, &len) == -1)
    {
        driver_.logError("could not query packet reserved space for '%s': %s", name_.c_str(), std::strerror(errno));
        return false;
    }
    tpReserve_ = static_cast<uint32_t>(val);

    if (!bindTo(0))
        return false;

    struct ifreq hw{};
    std::strncpy(hw.ifr_name, name_.c_str(), sizeof(hw.ifr_name) - 1);
    if (::ioctl(fd_, SIOCGIFHWADDR, &hw) == -1)
    {
        driver_.logError("SIOCGIFHWADDR failed for %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }
    const int arptype = hw.ifr_hwaddr.sa_family;
    if (arptype != ARPHRD_ETHER && arptype != ARPHRD_LOOPBACK)
    {
        driver_.logError("invalid interface type for %s: %d", name_.c_str(), arptype);
        return false;
    }

    struct packet_mreq mr{};
    mr.mr_ifindex = static_cast<int>(index_);
    mr.mr_type = PACKET_MR_PROMISC;
    if (::setsockopt(fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1)
    {
        driver_.logError("could not enable promiscuous mode on %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }

    return true;
}

void Instance::destroy()
{
    if (fd_ == -1)
        return;

    if (rxRing.entries)
    {
        ::free(rxRing.entries);
        rxRing.entries = nullptr;
    }
    if (txRing.entries)
    {
        ::free(txRing.entries);
        txRing.entries = nullptr;
    }

    if (buffer_ && buffer_ != MAP_FAILED)
    {
        ::munmap(buffer_, rxRing.size + txRing.size);
        buffer_ = MAP_FAILED;
    }

    struct tpacket_req req{};
    ::setsockopt(fd_, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    if (txRing.size)
        ::setsockopt(fd_, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));

    ::close(fd_);
    fd_ = -1;
}

bool Instance::bindTo(int protocol)
{
    struct sockaddr_ll sll{};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = static_cast<int>(index_);
    sll.sll_protocol = htons(static_cast<uint16_t>(protocol));

    if (::bind(fd_, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) == -1)
    {
        driver_.logError("bind(%s): %s", name_.c_str(), std::strerror(errno));
        return false;
    }

    int err = 0;
    socklen_t errlen = sizeof(err);
    if (::getsockopt(fd_, SOL_SOCKET, SO_ERROR, &err, &errlen) || err)
    {
        driver_.logError("getsockopt(SO_ERROR) on %s: %s", name_.c_str(), err ? std::strerror(err) : std::strerror(errno));
        return false;
    }
    return true;
}

} // namespace snet::driver