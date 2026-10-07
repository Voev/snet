#include "afpacket_instance.hpp"
#include "afpacket_driver.hpp"

#include <arpa/inet.h>

#include <cstring>
#include <cerrno>

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <net/if_arp.h>

#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include <unistd.h>

namespace snet::driver
{

Instance::Instance(AFPacketDriver& driver, io::DeviceId id)
    : driver_(driver)
    , id_(id)
{
}

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

    // PACKET_IGNORE_OUTGOING

    int on = 1;
    if (::setsockopt(fd_, SOL_PACKET, PACKET_IGNORE_OUTGOING, &on, sizeof(on)) < 0)
    {
        driver_.logWarning("PACKET_IGNORE_OUTGOING not supported: %s", std::strerror(errno));
    }
    else
    {
        driver_.logInfo("PACKET_IGNORE_OUTGOING enabled on %s", name.c_str());
    }

    // Index of interface

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, name_.c_str(), sizeof(ifr.ifr_name) - 1);

    if (::ioctl(fd_, SIOCGIFINDEX, &ifr) == -1)
    {
        driver_.logError("could not find index for device %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }

    index_ = static_cast<uint32_t>(ifr.ifr_ifindex);

    // TPACKET_V2
    int val = TPACKET_V2;
    if (::setsockopt(fd_, SOL_PACKET, PACKET_VERSION, &val, sizeof(val)) < 0)
    {
        driver_.logError("couldn't activate TPACKET_V2 on %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }

    socklen_t len = sizeof(val);
    if (::getsockopt(fd_, SOL_PACKET, PACKET_HDRLEN, &val, &len) < 0)
    {
        driver_.logError("couldn't retrieve TPACKET_V2 header length on %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }
    tpHdrlen_ = static_cast<uint32_t>(val);

    // PACKET_RESERVE

    val = static_cast<int>(kVlanTagLen);
    if (::setsockopt(fd_, SOL_PACKET, PACKET_RESERVE, &val, sizeof(val)) < 0)
    {
        driver_.logError("couldn't set up %d-byte reservation on %s: %s", val, name_.c_str(), std::strerror(errno));
        return false;
    }

    // QDISC_BYPASS

    val = 1;
    if (::setsockopt(fd_, SOL_PACKET, PACKET_QDISC_BYPASS, &val, sizeof(val)) < 0)
    {
        driver_.logError("couldn't configure qdisc bypass on %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }

    // PACKET_LOSS

    if (::setsockopt(fd_, SOL_PACKET, PACKET_LOSS, &val, sizeof(val)) < 0)
    {
        driver_.logError("couldn't configure PACKET_LOSS on %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }

    // MTU

    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, name_.c_str(), sizeof(ifr.ifr_name) - 1);
    if (::ioctl(fd_, SIOCGIFMTU, &ifr) == -1)
    {
        driver_.logError("could not query MTU for '%s': %s", name_.c_str(), std::strerror(errno));
        return false;
    }
    mtu_ = ifr.ifr_mtu;

    // Interface status

    struct ifreq flags{};
    std::strncpy(flags.ifr_name, name_.c_str(), sizeof(flags.ifr_name) - 1);
    if (::ioctl(fd_, SIOCGIFFLAGS, &flags) == 0)
    {
        up_ = (flags.ifr_flags & IFF_UP) != 0;
    }

    if (::getsockopt(fd_, SOL_PACKET, PACKET_RESERVE, &val, &len) == -1)
    {
        driver_.logError("could not query packet reserved space for '%s': %s", name_.c_str(), std::strerror(errno));
        return false;
    }
    tpReserve_ = static_cast<uint32_t>(val);

    struct ifreq hw{};
    std::strncpy(hw.ifr_name, name_.c_str(), sizeof(hw.ifr_name) - 1);
    if (::ioctl(fd_, SIOCGIFHWADDR, &hw) == -1)
    {
        driver_.logError("SIOCGIFHWADDR failed for %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }
    std::memcpy(mac_.data(), hw.ifr_hwaddr.sa_data, 6);

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

    if (rxRing_.entries)
    {
        ::free(rxRing_.entries);
        rxRing_.entries = nullptr;
    }
    if (txRing_.entries)
    {
        ::free(txRing_.entries);
        txRing_.entries = nullptr;
    }

    if (buffer_ && buffer_ != MAP_FAILED)
    {
        ::munmap(buffer_, rxRing_.size + txRing_.size);
        buffer_ = MAP_FAILED;
    }

    struct tpacket_req req{};
    ::setsockopt(fd_, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    if (txRing_.size)
        ::setsockopt(fd_, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));

    ::close(fd_);
    fd_ = -1;
}

bool Instance::createRings(const RingConfig& cfg)
{
    ringSizeHint_ = cfg.ringSizeHint;
    snaplenCfg_ = cfg.snaplen;
    useTxRing_ = cfg.useTxRing;

    if (!calculateFrameSize(snaplenCfg_))
        return false;
    if (!createRxRing())
        return false;
    if (useTxRing_ && !createTxRing())
        return false;

    if (!mmapRings())
        return false;
    if (!setupRing(rxRing_))
        return false;
    if (txRing_.size && !setupRing(txRing_))
        return false;
    return true;
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
        auto* msg = err ? std::strerror(err) : std::strerror(errno);
        driver_.logError("getsockopt(SO_ERROR) on %s: %s", name_.c_str(), msg);
        return false;
    }

    return true;
}

bool Instance::configureFanout(afpacket::Fanout::Type fanoutType, afpacket::Fanout::Flags fanoutFlags)
{
    afpacket::Fanout fanout(fanoutType, fanoutFlags, static_cast<uint16_t>(index_));
    const uint32_t arg = fanout.value();

    if (::setsockopt(fd_, SOL_PACKET, PACKET_FANOUT, &arg, sizeof(arg)) == -1)
    {
        driver_.logError("could not configure packet fanout on %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }

    return true;
}

bool Instance::calculateFrameSize(uint32_t snaplen)
{
    const unsigned tpHdrlenSll = SNET_TPACKET_ALIGN(tpHdrlen_) + sizeof(sockaddr_ll);
    const unsigned netoff = SNET_TPACKET_ALIGN(tpHdrlenSll + (ETH_HLEN < 16 ? 16 : ETH_HLEN)) + tpReserve_;
    const unsigned macoff = netoff - ETH_HLEN;
    const unsigned frameSize = SNET_TPACKET_ALIGN(macoff + snaplen);

    tpFrameSize_ = frameSize;
    actualSnaplen_ = frameSize - macoff;
    macoff_ = macoff;
    return true;
}

bool Instance::calculateLayout(tpacket_req& layout, int order) const
{
    layout.tp_frame_size = tpFrameSize_;
    layout.tp_block_size = static_cast<unsigned>(::getpagesize()) << order;
    while (layout.tp_block_size < layout.tp_frame_size)
        layout.tp_block_size <<= 1;

    const unsigned framesPerBlock = layout.tp_block_size / layout.tp_frame_size;
    if (framesPerBlock == 0)
    {
        driver_.logError(
            "invalid frames per block (%u/%u) for %s", layout.tp_block_size, layout.tp_frame_size, name_.c_str());
        return false;
    }

    layout.tp_frame_nr = ringSizeHint_ / layout.tp_frame_size;
    layout.tp_block_nr = layout.tp_frame_nr / framesPerBlock;
    layout.tp_frame_nr = layout.tp_block_nr * framesPerBlock;

    driver_.logInfo("afpacket[%s] layout: frame=%u frames=%u block=%u blocks=%u",
                    name_.c_str(),
                    layout.tp_frame_size,
                    layout.tp_frame_nr,
                    layout.tp_block_size,
                    layout.tp_block_nr);
    return true;
}

bool Instance::createRxRing()
{
    for (int order = kDefaultOrder; order >= 0; --order)
    {
        tpacket_req layout{};
        if (!calculateLayout(layout, order))
            return false;

        if (::setsockopt(fd_, SOL_PACKET, PACKET_RX_RING, &layout, sizeof(layout)) == 0)
        {
            rxRing_.layout = layout;
            rxRing_.size = layout.tp_block_size * layout.tp_block_nr;
            return true;
        }
        if (errno == ENOMEM)
        {
            driver_.logInfo("RX ring on %s order %d failed, retrying...", name_.c_str(), order);
            continue;
        }
        driver_.logError("couldn't create RX ring on %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }
    driver_.logError("couldn't allocate enough memory for RX ring on %s", name_.c_str());
    return false;
}

bool Instance::createTxRing()
{
    for (int order = kDefaultOrder; order >= 0; --order)
    {
        tpacket_req layout{};
        if (!calculateLayout(layout, order))
            return false;

        if (::setsockopt(fd_, SOL_PACKET, PACKET_TX_RING, &layout, sizeof(layout)) == 0)
        {
            txRing_.layout = layout;
            txRing_.size = layout.tp_block_size * layout.tp_block_nr;
            return true;
        }
        if (errno == ENOMEM)
            continue;
        driver_.logError("couldn't create TX ring on %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }
    driver_.logError("couldn't allocate enough memory for TX ring on %s", name_.c_str());
    return false;
}

bool Instance::mmapRings()
{
    const unsigned ringSize = rxRing_.size + txRing_.size;
    void* buf = ::mmap(nullptr, ringSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
    if (buf == MAP_FAILED)
    {
        driver_.logError("could not MMAP rings on %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }
    buffer_ = buf;
    rxRing_.start = buf;
    if (txRing_.size)
        txRing_.start = static_cast<uint8_t*>(buf) + rxRing_.size;
    return true;
}

bool Instance::setupRing(Ring& ring)
{
    ring.entries = static_cast<RingEntry*>(::calloc(ring.layout.tp_frame_nr, sizeof(RingEntry)));
    if (!ring.entries)
    {
        driver_.logError("could not allocate ring entries on %s", name_.c_str());
        return false;
    }

    unsigned idx = 0;
    for (unsigned block = 0; block < ring.layout.tp_block_nr; ++block)
    {
        const unsigned blockOffset = block * ring.layout.tp_block_size;
        const unsigned framesPerBlock = ring.layout.tp_block_size / ring.layout.tp_frame_size;
        for (unsigned frame = 0; frame < framesPerBlock && idx < ring.layout.tp_frame_nr; ++frame)
        {
            const unsigned frameOffset = frame * ring.layout.tp_frame_size;
            ring.entries[idx].raw = static_cast<uint8_t*>(ring.start) + blockOffset + frameOffset;
            ring.entries[idx].next = &ring.entries[idx + 1];
            ++idx;
        }
    }
    ring.entries[ring.layout.tp_frame_nr - 1].next = &ring.entries[0];
    ring.cursor = &ring.entries[0];
    return true;
}

// Receive methods

Instance::RxStatus Instance::receive(RxFrame& out) noexcept
{
    if (!rxRing_.cursor || !rxRing_.entries)
        return RxStatus::NoPacket;

    auto* hdr = reinterpret_cast<tpacket2_hdr*>(rxRing_.cursor->raw);
    if (!(hdr->tp_status & TP_STATUS_USER))
        return RxStatus::NoPacket;

    const uint32_t tpLen = hdr->tp_len;
    const uint32_t tpMac = hdr->tp_mac;
    uint32_t tpSnaplen = hdr->tp_snaplen;

    if (tpMac + tpSnaplen > rxRing_.layout.tp_frame_size)
    {
        driver_.logError("corrupted frame on %s (MAC %u + CapLen %u > FrameSize %u)",
                         name_.c_str(),
                         tpMac,
                         tpSnaplen,
                         rxRing_.layout.tp_frame_size);
        hdr->tp_status = TP_STATUS_KERNEL;
        rxRing_.cursor = rxRing_.cursor->next;
        return RxStatus::Corrupt;
    }

    uint8_t* data = rxRing_.cursor->raw + tpMac;

    if ((hdr->tp_vlan_tci || (hdr->tp_status & TP_STATUS_VLAN_VALID)) &&
        tpSnaplen >= static_cast<uint32_t>(kVlanOffset))
    {
        data -= kVlanTagLen;
        std::memmove(data, data + kVlanTagLen, kVlanOffset);

        auto* tag = reinterpret_cast<VlanTag*>(data + kVlanOffset);
        tag->tpid = (hdr->tp_vlan_tpid && (hdr->tp_status & TP_STATUS_VLAN_TPID_VALID)) ? htons(hdr->tp_vlan_tpid)
                                                                                        : htons(ETH_P_8021Q);
        tag->tci = htons(hdr->tp_vlan_tci);
        tpSnaplen += kVlanTagLen;
    }

    out.data = data;
    out.caplen = tpSnaplen;
    out.len = tpLen;
    out.entry = rxRing_.cursor;

    rxRing_.cursor = rxRing_.cursor->next;
    return RxStatus::Ok;
}

void Instance::releaseFrame(RingEntry* entry) noexcept
{
    if (!entry)
        return;
    auto* hdr = reinterpret_cast<tpacket2_hdr*>(entry->raw);
    hdr->tp_status = TP_STATUS_KERNEL;
}

void Instance::releaseOutstandingFrames() noexcept
{
    if (!rxRing_.entries)
        return;
    for (uint32_t i = 0; i < rxRing_.layout.tp_frame_nr; ++i)
    {
        auto* hdr = reinterpret_cast<tpacket2_hdr*>(rxRing_.entries[i].raw);
        if (hdr->tp_status & TP_STATUS_USER)
            hdr->tp_status = TP_STATUS_KERNEL;
    }
}

// Transmit methods

bool Instance::send(const uint8_t* data, size_t length) noexcept
{
    return txRing_.size ? sendRing(data, length) : sendDirect(data, length);
}

bool Instance::sendRing(const uint8_t* data, size_t length) noexcept
{
    auto* entry = txRing_.cursor;
    if (!entry)
        return false;

    auto* hdr = reinterpret_cast<tpacket2_hdr*>(entry->raw);
    if (hdr->tp_status != TP_STATUS_AVAILABLE)
    {
        driver_.logError("TX ring on %s is full", name_.c_str());
        return false;
    }

    hdr->tp_mac = static_cast<uint16_t>(macoff_);

    std::memcpy(entry->raw + macoff_, data, length);

    hdr->tp_len = static_cast<unsigned int>(length);
    hdr->tp_status = TP_STATUS_SEND_REQUEST;

    if (::send(fd_, nullptr, 0, 0) < 0)
    {
        driver_.logError("send() via TX ring on %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }

    txRing_.cursor = entry->next;
    return true;
}

bool Instance::sendDirect(const uint8_t* data, size_t length) noexcept
{
    while (::send(fd_, data, length, 0) < 0)
    {
        if (errno == ENOBUFS)
        {
            struct pollfd pfd{};
            pfd.fd = fd_;
            pfd.events = POLLOUT;
            if (::poll(&pfd, 1, 10) > 0 && (pfd.revents & POLLOUT))
            {
                continue;
            }
        }
        driver_.logError("error sending data over socket %s: %s", name_.c_str(), std::strerror(errno));
        return false;
    }
    return true;
}

} // namespace snet::driver