// xdp_driver.cpp
#include "xdp_driver.hpp"

#include <cerrno>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <casket/log/log.hpp>
#include <casket/opt/opt.hpp>

#include <snet/layers/header_builder.hpp>
#include <snet/layers/in_memory_packet.hpp>

using namespace casket::opt;
using namespace snet::io;

namespace snet::driver
{

/// Returns the interface index for the given name, or 0 on error.
static uint32_t getIfIndex(const std::string& ifname)
{
    return if_nametoindex(ifname.c_str());
}

/// Reads IPv4 address and netmask of the given interface.
static bool getIfIpAndMask(const std::string& ifname, uint32_t& ip, uint32_t& mask)
{
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);

    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return false;

    bool ok = false;
    if (::ioctl(fd, SIOCGIFADDR, &ifr) == 0)
    {
        ip = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr)->sin_addr.s_addr;
        if (::ioctl(fd, SIOCGIFNETMASK, &ifr) == 0)
        {
            mask = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_netmask)->sin_addr.s_addr;
            ok = true;
        }
    }

    ::close(fd);
    return ok;
}

/// Reads the hardware (MAC) address of the given interface.
static bool getIfMac(const std::string& ifname, layers::MacAddress& mac)
{
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);

    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return false;

    bool ok = false;
    if (::ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
    {
        std::memcpy(mac.bytes.data(), ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        ok = true;
    }

    ::close(fd);
    return ok;
}

XdpDriver::XdpDriver(const io::DriverSpec& config)
    : DriverBase(config)
{
    logInfo("XdpDriver constructed");
}

XdpDriver::~XdpDriver() noexcept
{
    cleanup();
}

std::shared_ptr<io::Driver> XdpDriver::create(const io::DriverSpec& config)
{
    return std::make_shared<XdpDriver>(config);
}

const char* XdpDriver::getName() const
{
    return "xdp";
}

Status XdpDriver::declareOptions(io::Config& config)
{
    // clang-format off
    config.addDriverOption(OptionBuilder("queue_id", Value(&queueId_))
        .setDefaultValue(0u)
        .setDescription("AF_XDP queue ID (0-based)")
        .build());

    config.addDriverOption(OptionBuilder("umem_num_frames", Value(&umemNumFrames_))
        .setDefaultValue(4096u)
        .setDescription("Number of UMEM frames (must be a power of 2)")
        .build());

    config.addDriverOption(OptionBuilder("umem_frame_size", Value(&umemFrameSize_))
        .setDefaultValue(2048u)
        .setDescription("Size of each UMEM frame in bytes")
        .build());

    config.addDriverOption(OptionBuilder("fill_ring_size", Value(&fillRingSize_))
        .setDefaultValue(2048u)
        .setDescription("Fill ring size (must be a power of 2)")
        .build());

    config.addDriverOption(OptionBuilder("completion_ring_size", Value(&completionRingSize_))
        .setDefaultValue(2048u)
        .setDescription("Completion ring size (must be a power of 2)")
        .build());

    config.addDriverOption(OptionBuilder("rx_ring_size", Value(&rxRingSize_))
        .setDefaultValue(2048u)
        .setDescription("RX ring size (must be a power of 2)")
        .build());

    config.addDriverOption(OptionBuilder("tx_ring_size", Value(&txRingSize_))
        .setDefaultValue(2048u)
        .setDescription("TX ring size (must be a power of 2)")
        .build());

    config.addDriverOption(OptionBuilder("batch_size", Value(&batchSize_))
        .setDefaultValue(64u)
        .setDescription("Batch size for RX/TX processing")
        .build());

    config.addDriverOption(OptionBuilder("zero_copy", Value(&zeroCopy_))
        .setDefaultValue(true)
        .setDescription("Use zero-copy mode (requires driver support)")
        .build());

    config.addDriverOption(OptionBuilder("use_skb_mode", Value(&useSkbMode_))
        .setDefaultValue(false)
        .setDescription("Use SKB (generic) XDP mode instead of native")
        .build());

    config.addDriverOption(OptionBuilder("bpf_filter", Value(&bpfFilter_))
        .setDescription("BPF filter string (e.g. 'tcp port 80')")
        .build());
    // clang-format on

    return Status::Success;
}

Status XdpDriver::configure(const snet::io::Config& config)
{
    snaplen_ = config.getSnaplen();

    // Parse the colon-separated device list, same convention as AFPacketDriver.
    const std::string& devs = config.getInput();
    if (devs.empty() || devs.front() == ':' || devs.back() == ':')
    {
        logError("invalid interface specification: '%s'", devs.c_str());
        return Status::InvalidArgument;
    }

    size_t pos = 0;
    while (pos < devs.size())
    {
        size_t colon = devs.find(':', pos);
        if (colon == std::string::npos)
            colon = devs.size();
        if (colon > pos)
        {
            std::string name = devs.substr(pos, colon - pos);
            if (name.size() >= IFNAMSIZ)
            {
                logError("interface name too long: '%s'", name.c_str());
                return Status::InvalidArgument;
            }
            devices_.push_back(std::move(name));
        }
        pos = colon + 1;
    }

    if (devices_.empty())
    {
        logError("no interfaces specified");
        return Status::InvalidArgument;
    }

    // Ring sizes and UMEM frame count must be powers of two.
    auto isPowerOfTwo = [](uint32_t v) { return v != 0 && (v & (v - 1)) == 0; };
    if (!isPowerOfTwo(umemNumFrames_) || !isPowerOfTwo(fillRingSize_) ||
        !isPowerOfTwo(completionRingSize_) || !isPowerOfTwo(rxRingSize_) ||
        !isPowerOfTwo(txRingSize_))
    {
        logError("ring sizes and UMEM frame count must be powers of two");
        return Status::InvalidArgument;
    }

    for (const auto& name : devices_)
    {
        auto inst = std::make_unique<XdpInstance>();
        inst->name = name;
        inst->ifindex = getIfIndex(name);
        if (inst->ifindex == 0)
        {
            logError("interface '%s' not found", name.c_str());
            return Status::NoSuchDevice;
        }

        if (!getIfIpAndMask(name, inst->ip, inst->netmask))
        {
            logError("failed to get IP/mask for '%s'", name.c_str());
            return Status::Error;
        }

        if (!getIfMac(name, inst->mac))
        {
            logError("failed to get MAC for '%s'", name.c_str());
            return Status::Error;
        }

        instances_.push_back(std::move(inst));
    }

    if (!setupUmem(umemNumFrames_, umemFrameSize_))
        return Status::Error;

    // For simplicity a single AF_XDP socket is used on the first device.
    // Multi-device setups need one XSK per interface/queue.
    if (!setupSocket(devices_[0], queueId_))
        return Status::Error;

    if (!loadXdpProgram(devices_[0], xskMapFd_))
        return Status::Error;

    uint32_t poolSize = config.getMsgPoolSize();
    if (poolSize == 0)
    {
        poolSize = umemNumFrames_ / 10;
        if (poolSize == 0)
            poolSize = 1;
    }
    pool_ = std::make_unique<XdpPool>(poolSize);

    if (!refillFillRing(fillRingSize_))
        return Status::Error;

    logInfo("XdpDriver configured: %zu device(s), queue=%u, umem_frames=%u",
            instances_.size(), queueId_, umemNumFrames_);

    return Status::Success;
}

bool XdpDriver::setupUmem(uint32_t numFrames, uint32_t frameSize)
{
    // Align frame size up to a page boundary.
    frameSize = (frameSize + getpagesize() - 1) & ~(getpagesize() - 1);

    size_t totalSize = static_cast<size_t>(numFrames) * frameSize;

    umem_.buffer = ::mmap(nullptr, totalSize, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (umem_.buffer == MAP_FAILED)
    {
        logError("failed to allocate UMEM: %s", std::strerror(errno));
        return false;
    }

    umem_.frameSize = frameSize;
    umem_.numFrames = numFrames;

    struct xdp_umem_reg reg{};
    reg.addr = reinterpret_cast<uint64_t>(umem_.buffer);
    reg.len = totalSize;
    reg.chunk_size = frameSize;
    reg.headroom = 0;
    reg.flags = 0;

    int fd = ::socket(AF_XDP, SOCK_RAW, 0);
    if (fd < 0)
    {
        logError("failed to create AF_XDP socket for UMEM: %s", std::strerror(errno));
        return false;
    }

    if (::setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg)) < 0)
    {
        logError("XDP_UMEM_REG failed: %s", std::strerror(errno));
        ::close(fd);
        return false;
    }

    int fillSize = static_cast<int>(fillRingSize_);
    if (::setsockopt(fd, SOL_XDP, XDP_UMEM_FILL_RING, &fillSize, sizeof(fillSize)) < 0)
    {
        logError("XDP_UMEM_FILL_RING failed: %s", std::strerror(errno));
        ::close(fd);
        return false;
    }

    int compSize = static_cast<int>(completionRingSize_);
    if (::setsockopt(fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &compSize, sizeof(compSize)) < 0)
    {
        logError("XDP_UMEM_COMPLETION_RING failed: %s", std::strerror(errno));
        ::close(fd);
        return false;
    }

    struct xsk_umem_config umemCfg{};
    umemCfg.fill_size = fillRingSize_;
    umemCfg.comp_size = completionRingSize_;
    umemCfg.frame_size = frameSize;
    umemCfg.frame_headroom = 0;
    umemCfg.flags = 0;

    if (xsk_umem__create(&umem_.umem, umem_.buffer, totalSize,
                         &umem_.fill, &umem_.comp, &umemCfg) != 0)
    {
        logError("xsk_umem__create failed");
        ::close(fd);
        return false;
    }

    ::close(fd);
    logInfo("UMEM created: %u frames x %u bytes = %zu MB",
            numFrames, frameSize, totalSize / (1024 * 1024));
    return true;
}

bool XdpDriver::setupSocket(const std::string& ifname, uint32_t queueId)
{
    struct xsk_socket_config cfg{};
    cfg.rx_ring_size = rxRingSize_;
    cfg.tx_ring_size = txRingSize_;
    cfg.libbpf_flags = 0;
    cfg.xdp_flags = useSkbMode_ ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;
    cfg.bind_flags = 0;

    if (zeroCopy_)
        cfg.bind_flags |= XDP_ZEROCOPY;
    else
        cfg.bind_flags |= XDP_COPY;

    int ret = xsk_socket__create(&socket_.xsk, ifname.c_str(), queueId,
                                  umem_.umem, &socket_.rx, &socket_.tx, &cfg);
    if (ret != 0)
    {
        logError("xsk_socket__create failed on %s queue %u: %s",
                 ifname.c_str(), queueId, std::strerror(-ret));
        return false;
    }

    socket_.fill = &umem_.fill;
    socket_.comp = &umem_.comp;
    socket_.rxBatchSize = batchSize_;
    socket_.txBatchSize = batchSize_;

    xskMapFd_ = xsk_socket__fd(socket_.xsk);
    if (xskMapFd_ < 0)
    {
        logError("failed to get XSK socket fd");
        return false;
    }

    logInfo("AF_XDP socket created on %s queue %u (zero-copy=%d)",
            ifname.c_str(), queueId, zeroCopy_);
    return true;
}

bool XdpDriver::loadXdpProgram(const std::string& ifname, int xskMapFd)
{
    // The XDP program is expected to redirect packets to the XSK map using
    // bpf_redirect_map() keyed by the RX queue index. A minimal program:
    //
    //   SEC("xdp")
    //   int xdp_redirect_prog(struct xdp_md *ctx) {
    //       int index = ctx->rx_queue_index;
    //       if (bpf_map_lookup_elem(&xsks_map, &index))
    //           return bpf_redirect_map(&xsks_map, index, 0);
    //       return XDP_PASS;
    //   }
    //
    // A production version would load this program with libbpf and attach it
    // to the interface via bpf_program__attach_xdp(). Here we only log the
    // expectation so the rest of the driver remains usable for integration.

    logInfo("XDP program should be loaded for interface '%s' "
            "(redirect to XSK map fd=%d). "
            "Use a BPF program with BPF_MAP_TYPE_XSKMAP and bpf_redirect_map().",
            ifname.c_str(), xskMapFd);

    xdpProgFd_ = -1;
    return true;
}

bool XdpDriver::refillFillRing(uint32_t count)
{
    uint32_t idx = 0;
    uint32_t produced = xsk_ring_prod__reserve(&umem_.fill, count, &idx);
    if (produced == 0)
    {
        logWarning("fill ring is full, cannot reserve %u entries", count);
        return false;
    }

    for (uint32_t i = 0; i < produced; ++i)
    {
        uint64_t addr = reinterpret_cast<uint64_t>(umem_.buffer) +
                        (static_cast<uint64_t>(idx + i) * umem_.frameSize);
        *xsk_ring_prod__fill_addr(&umem_.fill, idx + i) = addr;
    }

    xsk_ring_prod__submit(&umem_.fill, produced);
    return true;
}

bool XdpDriver::processCompletionRing()
{
    uint32_t idx = 0;
    uint32_t completed = xsk_ring_cons__peek(&umem_.comp, batchSize_, &idx);
    if (completed == 0)
        return true;

    for (uint32_t i = 0; i < completed; ++i)
    {
        uint64_t addr = *xsk_ring_cons__comp_addr(&umem_.comp, idx + i);

        // Return the completed frame back into the fill ring.
        uint32_t fillIdx = 0;
        if (xsk_ring_prod__reserve(&umem_.fill, 1, &fillIdx) == 1)
        {
            *xsk_ring_prod__fill_addr(&umem_.fill, fillIdx) = addr;
            xsk_ring_prod__submit(&umem_.fill, 1);
        }
    }

    xsk_ring_cons__release(&umem_.comp, completed);
    socket_.outstandingTx -= completed;
    return true;
}

Status XdpDriver::start()
{
    if (!socket_.xsk)
    {
        logError("start() called before configure()");
        return Status::InvalidArgument;
    }

    resetStats();
    logInfo("XdpDriver started");
    return Status::Success;
}

Status XdpDriver::stop()
{
    logInfo("XdpDriver stopping");
    cleanup();
    return Status::Success;
}

Status XdpDriver::interrupt()
{
    interrupted_.store(true, std::memory_order_release);
    return Status::Success;
}

RecvStatus XdpDriver::receivePackets(snet::layers::Packet** rawPacket,
                                      uint16_t* packetCount,
                                      uint16_t maxCount)
{
    if (!rawPacket || !packetCount || maxCount == 0)
    {
        if (packetCount)
            *packetCount = 0;
        return RecvStatus::Ok;
    }

    if (!pool_ || !socket_.xsk)
    {
        logError("receivePackets called before configure()");
        *packetCount = 0;
        return RecvStatus::Error;
    }

    uint16_t idx = 0;
    RecvStatus status = RecvStatus::Ok;

    // Reclaim TX frames before processing RX.
    processCompletionRing();

    while (idx < maxCount)
    {
        if (interrupted_.load(std::memory_order_acquire))
        {
            interrupted_.store(false, std::memory_order_release);
            status = RecvStatus::Interrupted;
            break;
        }

        XdpWrapper* wrapper = pool_->acquire();
        if (!wrapper)
        {
            logError("no free XdpWrapper (pool exhausted)");
            status = RecvStatus::NoBuffer;
            break;
        }

        uint32_t rxIdx = 0;
        uint32_t rcvd = xsk_ring_cons__peek(&socket_.rx, 1, &rxIdx);
        if (rcvd == 0)
        {
            pool_->release(wrapper);
            if (idx != 0)
            {
                status = RecvStatus::WouldBlock;
                break;
            }
            status = waitForPacket();
            if (status != RecvStatus::Ok)
                break;
            continue;
        }

        const struct xdp_desc* desc = xsk_ring_cons__rx_desc(&socket_.rx, rxIdx);
        uint64_t addr = desc->addr;
        uint32_t len = desc->len;

        uint8_t* data = reinterpret_cast<uint8_t*>(addr);

        wrapper->attach(data, len, len, nullptr, nullptr);
        rawPacket[idx++] = wrapper->asPacket();

        xsk_ring_cons__release(&socket_.rx, 1);

        stats_.packetsReceived++;
    }

    // Replenish the fill ring with frames consumed during this call.
    refillFillRing(fillRingSize_ / 2);

    *packetCount = idx;
    return status;
}

RecvStatus XdpDriver::waitForPacket()
{
    struct pollfd pfd{};
    pfd.fd = xsk_socket__fd(socket_.xsk);
    pfd.events = POLLIN;
    pfd.revents = 0;

    while (true)
    {
        if (interrupted_.load(std::memory_order_acquire))
        {
            interrupted_.store(false, std::memory_order_release);
            return RecvStatus::Interrupted;
        }

        int ret = ::poll(&pfd, 1, 1000);
        if (ret > 0)
        {
            if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
            {
                logError("error condition on AF_XDP socket");
                return RecvStatus::Error;
            }
            return RecvStatus::Ok;
        }
        if (ret < 0 && errno != EINTR)
        {
            logError("poll failed: %s", std::strerror(errno));
            return RecvStatus::Error;
        }
    }
}

Status XdpDriver::finalizePacket(snet::layers::Packet* rawPacket, Verdict verdict)
{
    if (!rawPacket)
    {
        logError("finalizePacket called with null packet");
        return Status::InvalidArgument;
    }

    XdpWrapper* wrapper = XdpWrapper::fromPacket(rawPacket);
    if (!wrapper)
    {
        logError("finalizePacket called with unknown packet");
        return Status::InvalidArgument;
    }

    stats_.verdicts[static_cast<size_t>(verdict)]++;

    const bool pass = (verdict == Verdict::Pass ||
                       verdict == Verdict::Replace ||
                       verdict == Verdict::Ignore);

    if (pass)
    {
        // In AF_XDP, "pass" means pushing the packet back to the network.
        // The frame is placed into the TX ring so the kernel driver sends
        // it out via XDP_TX without ever entering the network stack.
        const uint8_t* frame = rawPacket->getData();
        uint32_t len = static_cast<uint32_t>(rawPacket->getDataLen());

        if (!transmitPacket(frame, len))
            logError("failed to transmit packet in finalizePacket");
    }

    pool_->release(wrapper);
    return Status::Success;
}

Status XdpDriver::inject(const uint8_t* data, uint32_t dataLen)
{
    if (!data || dataLen < 20)
        return Status::InvalidArgument;

    const uint8_t version = data[0] >> 4;
    if (version != 4)
    {
        logError("inject: unsupported L3 version %u", version);
        return Status::InvalidArgument;
    }

    if (!transmitPacket(data, dataLen))
        return Status::Error;

    stats_.packetsInjected++;
    return Status::Success;
}

Status XdpDriver::injectPacket(layers::Packet* rawPacket)
{
    if (!rawPacket)
        return Status::InvalidArgument;

    const uint8_t* ipData = rawPacket->getData();
    uint32_t ipLen = static_cast<uint32_t>(rawPacket->getDataLen());

    if (ipLen < 20 || (ipData[0] >> 4) != 4)
    {
        logError("inject: not IPv4");
        return Status::InvalidArgument;
    }

    auto* memPkt = layers::InMemoryPacket::fromPacket(rawPacket);
    if (!memPkt)
        return Status::Error;

    const size_t headroom = memPkt->headroom();
    if (headroom < ETH_HLEN)
        return Status::InvalidArgument;

    uint8_t* eth = memPkt->getBufferStart();
    layers::MacAddress srcMac = instances_[0]->mac;
    layers::MacAddress dstMac{};

    // Broadcast MAC is used as a placeholder; a real implementation would
    // look up the neighbour entry, for example via /proc/net/arp.
    std::memset(dstMac.bytes.data(), 0xFF, ETH_ALEN);

    layers::HeaderBuilder<layers::ethernet_header> builder(eth, headroom,
        [](size_t) noexcept {});
    builder.set(&layers::ethernet_header::dstMac, dstMac.bytes)
           .set(&layers::ethernet_header::srcMac, srcMac.bytes)
           .set(&layers::ethernet_header::etherType,
                casket::host_to_be(static_cast<uint16_t>(layers::EtherType::IP)))
           .build();

    uint32_t frameLen = ETH_HLEN + ipLen;

    if (!transmitPacket(eth, frameLen))
        return Status::Error;

    stats_.packetsInjected++;
    return Status::Success;
}

bool XdpDriver::transmitPacket(const uint8_t* data, uint32_t len)
{
    if (!socket_.xsk)
        return false;

    uint32_t txIdx = 0;
    if (xsk_ring_prod__reserve(&socket_.tx, 1, &txIdx) != 1)
    {
        logError("TX ring is full");
        return false;
    }

    struct xdp_desc* desc = xsk_ring_prod__tx_desc(&socket_.tx, txIdx);

    // Simple rotating allocation of UMEM frames for TX.
    uint64_t addr = reinterpret_cast<uint64_t>(umem_.buffer) +
                    (socket_.outstandingTx % umem_.numFrames) * umem_.frameSize;

    std::memcpy(reinterpret_cast<void*>(addr), data, len);

    desc->addr = addr;
    desc->len = len;
    socket_.outstandingTx++;

    xsk_ring_prod__submit(&socket_.tx, 1);

    if (::sendto(xsk_socket__fd(socket_.xsk), nullptr, 0, MSG_DONTWAIT,
                 nullptr, 0) < 0)
    {
        if (errno != EAGAIN && errno != ENOBUFS)
        {
            logError("sendto failed: %s", std::strerror(errno));
            return false;
        }
    }

    stats_.packetsSent++;
    return true;
}

Status XdpDriver::getStats(Stats* stats)
{
    if (stats)
        *stats = stats_;
    return Status::Success;
}

void XdpDriver::resetStats()
{
    stats_ = Stats{};
}

int XdpDriver::getSnaplen() const
{
    return static_cast<int>(snaplen_);
}

snet::layers::LinkLayerType XdpDriver::getDataLinkType() const
{
    return snet::layers::LinkLayerType::LINKTYPE_ETHERNET;
}

Status XdpDriver::getMsgPoolInfo(snet::io::PacketPoolInfo& info)
{
    auto capacity = pool_ ? pool_->capacity() : 0u;
    auto available = pool_ ? pool_->available() : 0u;

    info.capacity = capacity;
    info.available = available;
    info.memorySize = sizeof(XdpWrapper) * capacity;
    return Status::Success;
}

XdpDriver::XdpInstance* XdpDriver::findEgress(uint32_t dstIp) const noexcept
{
    for (const auto& inst : instances_)
    {
        if (inst->netmask == 0)
            continue;
        if ((dstIp & inst->netmask) == (inst->ip & inst->netmask))
            return inst.get();
    }
    return nullptr;
}

void XdpDriver::cleanup()
{
    if (socket_.xsk)
    {
        xsk_socket__delete(socket_.xsk);
        socket_.xsk = nullptr;
    }

    if (umem_.umem)
    {
        xsk_umem__delete(umem_.umem);
        umem_.umem = nullptr;
    }

    if (umem_.buffer && umem_.buffer != MAP_FAILED)
    {
        size_t totalSize = static_cast<size_t>(umem_.numFrames) * umem_.frameSize;
        ::munmap(umem_.buffer, totalSize);
        umem_.buffer = nullptr;
    }

    if (xdpProgFd_ >= 0)
    {
        ::close(xdpProgFd_);
        xdpProgFd_ = -1;
    }

    pool_.reset();
}

} // namespace snet::driver

SNET_DLL_ALIAS(snet::driver::XdpDriver::create, CreateXdpDriver)