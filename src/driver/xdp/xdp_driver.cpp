#include "xdp_driver.hpp"

#include <cerrno>
#include <cstring>
#include <cstdio>
#include <cstdlib>

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

#include <xdp/libxdp.h>

using namespace casket::opt;
using namespace snet::io;

namespace snet::driver
{

namespace
{

uint32_t getIfIndex(const std::string& ifname)
{
    return if_nametoindex(ifname.c_str());
}

bool getIfIpAndMask(const std::string& ifname, uint32_t& ip, uint32_t& mask)
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

bool getIfMac(const std::string& ifname, layers::MacAddress& mac)
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

bool isPowerOfTwo(uint32_t v)
{
    return v != 0 && (v & (v - 1)) == 0;
}

/// Disables LRO on the interface. XDP requires LRO to be off on veth and
/// hv_netvsc, otherwise attaching the program fails.
bool disableLro(const std::string& ifname)
{
    std::string cmd = "ethtool -K " + ifname + " lro off 2>/dev/null";
    int rc = std::system(cmd.c_str());
    return rc == 0;
}

} // namespace

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

    config.addDriverOption(OptionBuilder("bpf_obj_path", Value(&bpfObjPath_))
        .setDefaultValue("xdp_redirect.bpf.o")
        .setDescription("Path to the compiled XDP BPF object file")
        .build());
    // clang-format on

    return Status::Success;
}

Status XdpDriver::configure(const snet::io::Config& config)
{
    snaplen_ = config.getSnaplen();

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

    if (!isPowerOfTwo(umemNumFrames_) || !isPowerOfTwo(fillRingSize_) || !isPowerOfTwo(completionRingSize_) ||
        !isPowerOfTwo(rxRingSize_) || !isPowerOfTwo(txRingSize_))
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

        // XDP requires LRO to be off.
        if (!disableLro(name))
        {
            logWarning("could not disable LRO on %s, XDP attach may fail", name.c_str());
        }

        instances_.push_back(std::move(inst));
    }

    // Pair interfaces for transparent bridge forwarding.
    if (instances_.size() == 1)
    {
        instances_[0]->peer = instances_[0].get();
    }
    else
    {
        for (size_t i = 0; i + 1 < instances_.size(); i += 2)
        {
            instances_[i]->peer = instances_[i + 1].get();
            instances_[i + 1]->peer = instances_[i].get();
        }
    }

    for (auto& inst : instances_)
{
    struct xdp_multiprog* mp = xdp_multiprog__get_from_ifindex(
        static_cast<int>(inst->ifindex));
    if (mp)
    {
        int err = xdp_multiprog__detach(mp);
        if (err)
            logWarning("xdp_multiprog__detach failed on %s: %s",
                       inst->name.c_str(), std::strerror(-err));
        else
            logInfo("Detached stale XDP program from %s", inst->name.c_str());
        xdp_multiprog__close(mp);
    }
}

    // Shared UMEM for all interfaces.
    if (!setupUmem(umemNumFrames_, umemFrameSize_))
        return Status::Error;

    for (size_t i = 0; i < instances_.size(); ++i)
    {
        if (!setupSocket(*instances_[i], queueId_, i == 0))
            return Status::Error;
    }

    // Load BPF object for each interface. Each interface gets its own
    // instance of the XDP program and its own XSK map, because the program
    // is attached per-interface.
    for (auto& inst : instances_)
    {
        if (!loadXdpProgram(*inst))
            return Status::Error;
    }

    // Attach the program to the interface before inserting the XSK fd,
    // because xsk_socket__create already registered the socket in the
    // kernel-side XSK map. The map must exist and the program must be
    // attached for traffic to be redirected.
    for (auto& inst : instances_)
    {
        if (!attachXdpProgram(*inst))
            return Status::Error;
        if (!insertXskIntoMap(*inst, queueId_))
            return Status::Error;
    }

    uint32_t poolSize = config.getMsgPoolSize();
    if (poolSize == 0)
    {
        poolSize = umemNumFrames_ / 10;
        if (poolSize == 0)
            poolSize = 1;
    }
    pool_ = std::make_unique<XdpPool>(poolSize);

    if (!refillFillRing(fillRingSize_))
    {
        logError("fill ring refill failed");
        return Status::Error;
    }
    logInfo("Fill ring refilled with %u entries", fillRingSize_);

    logInfo("XdpDriver configured: %zu interface(s), queue=%u, umem_frames=%u",
            instances_.size(),
            queueId_,
            umemNumFrames_);

    return Status::Success;
}

bool XdpDriver::setupUmem(uint32_t numFrames, uint32_t frameSize)
{
    frameSize = (frameSize + getpagesize() - 1) & ~(getpagesize() - 1);

    size_t totalSize = static_cast<size_t>(numFrames) * frameSize;

    umem_.buffer = ::mmap(nullptr, totalSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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

    if (xsk_umem__create(&umem_.umem, umem_.buffer, totalSize, &umem_.fill, &umem_.comp, &umemCfg) != 0)
    {
        logError("xsk_umem__create failed");
        ::close(fd);
        return false;
    }

    ::close(fd);
    logInfo("UMEM created: %u frames x %u bytes = %zu MB", numFrames, frameSize, totalSize / (1024 * 1024));
    return true;
}

bool XdpDriver::setupSocket(XdpInstance& inst, uint32_t queueId, bool isFirst)
{
    struct xsk_socket_config cfg{};
    cfg.rx_size = rxRingSize_;
    cfg.tx_size = txRingSize_;
    cfg.libbpf_flags = 0;
    cfg.xdp_flags = useSkbMode_ ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;
    cfg.bind_flags = 0;

    if (zeroCopy_)
        cfg.bind_flags |= XDP_ZEROCOPY;
    else
        cfg.bind_flags |= XDP_COPY;

    int ret;
    if (isFirst)
    {
        ret = xsk_socket__create(
            &inst.socket.xsk, inst.name.c_str(), queueId, umem_.umem, &inst.socket.rx, &inst.socket.tx, &cfg);
    }
    else
    {
        ret = xsk_socket__create_shared(&inst.socket.xsk,
                                        inst.name.c_str(),
                                        queueId,
                                        umem_.umem,
                                        &inst.socket.rx,
                                        &inst.socket.tx,
                                        &umem_.fill,
                                        &umem_.comp,
                                        &cfg);
    }

    if (ret != 0)
    {
        logError("xsk_socket__create%s failed on %s queue %u: %s",
                 isFirst ? "" : "_shared",
                 inst.name.c_str(),
                 queueId,
                 std::strerror(-ret));
        return false;
    }

    inst.socket.rxBatchSize = batchSize_;
    inst.socket.txBatchSize = batchSize_;

    inst.xskFd = xsk_socket__fd(inst.socket.xsk);
    if (inst.xskFd < 0)
    {
        logError("failed to get XSK socket fd for %s", inst.name.c_str());
        return false;
    }

    logInfo("AF_XDP socket created on %s queue %u (zero-copy=%d, shared=%d)",
            inst.name.c_str(),
            queueId,
            zeroCopy_,
            !isFirst);
    return true;
}

bool XdpDriver::loadXdpProgram(XdpInstance& inst)
{
    struct bpf_object* obj = bpf_object__open_file(bpfObjPath_.c_str(), nullptr);
    if (!obj)
    {
        logError("failed to open BPF object '%s' for %s", bpfObjPath_.c_str(), inst.name.c_str());
        return false;
    }

    if (bpf_object__load(obj) != 0)
    {
        logError("failed to load BPF object '%s' for %s", bpfObjPath_.c_str(), inst.name.c_str());
        bpf_object__close(obj);
        return false;
    }

    struct bpf_program* prog = bpf_object__find_program_by_name(obj, "xdp_redirect_prog");
    if (!prog)
    {
        logError("BPF program 'xdp_redirect_prog' not found in '%s'", bpfObjPath_.c_str());
        bpf_object__close(obj);
        return false;
    }

    struct bpf_map* map = bpf_object__find_map_by_name(obj, "xsks_map");
    if (!map)
    {
        logError("BPF map 'xsks_map' not found in '%s'", bpfObjPath_.c_str());
        bpf_object__close(obj);
        return false;
    }

    inst.xdpProgFd = bpf_program__fd(prog);
    inst.xskMapFd = bpf_map__fd(map);
    inst.bpfObj = obj;

    logInfo("BPF object loaded for %s: prog_fd=%d, map_fd=%d", inst.name.c_str(), inst.xdpProgFd, inst.xskMapFd);
    return true;
}

bool XdpDriver::attachXdpProgram(XdpInstance& inst)
{
    __u32 flags = useSkbMode_ ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;
    flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;

    int err = bpf_xdp_attach(static_cast<int>(inst.ifindex), inst.xdpProgFd, flags, nullptr);

    if (err < 0 && (err == -EBUSY || errno == EBUSY))
    {
        // На интерфейсе уже висит XDP-программа от предыдущего запуска.
        // Отвязываем её и пробуем снова.
        logWarning("XDP already attached to %s, detaching old program first", inst.name.c_str());

        // fd = -1 означает "отвязать текущую программу"
        int detachErr = bpf_xdp_attach(static_cast<int>(inst.ifindex), -1, flags, nullptr);
        if (detachErr < 0)
        {
            logError("failed to detach old XDP program from %s: %s", inst.name.c_str(), std::strerror(-detachErr));
            return false;
        }

        // Повторная попытка привязки
        err = bpf_xdp_attach(static_cast<int>(inst.ifindex), inst.xdpProgFd, flags, nullptr);
    }

    if (err < 0)
    {
        logError("failed to attach XDP program to %s (ifindex=%u): %s",
                 inst.name.c_str(),
                 inst.ifindex,
                 std::strerror(-err));
        return false;
    }

    logInfo("XDP program attached to %s (ifindex=%u, flags=0x%x)", inst.name.c_str(), inst.ifindex, flags);
    return true;
}

bool XdpDriver::insertXskIntoMap(XdpInstance& inst, uint32_t queueId)
{
    uint32_t key = queueId;
    if (bpf_map_update_elem(inst.xskMapFd, &key, &inst.xskFd, BPF_ANY) != 0)
    {
        logError("failed to insert XSK fd into XSK map for %s: %s", inst.name.c_str(), std::strerror(errno));
        return false;
    }

    logInfo("XSK fd %d inserted into XSK map for %s (queue %u)", inst.xskFd, inst.name.c_str(), queueId);
    return true;
}

void XdpDriver::unloadXdpProgram(XdpInstance& inst)
{
    if (inst.ifindex && inst.xdpProgFd >= 0)
    {
        bpf_xdp_detach(static_cast<int>(inst.ifindex), 0, nullptr);
    }
    if (inst.bpfObj)
    {
        bpf_object__close(inst.bpfObj);
        inst.bpfObj = nullptr;
    }
    inst.xdpProgFd = -1;
    inst.xskMapFd = -1;
}

bool XdpDriver::refillFillRing(uint32_t count)
{
    uint32_t idx = 0;
    uint32_t produced = xsk_ring_prod__reserve(&umem_.fill, count, &idx);
    logInfo("refillFillRing: count=%u, produced=%u", count, produced);

    if (produced == 0)
    {
        logWarning("fill ring is full, cannot reserve %u entries", count);
        return false;
    }

    for (uint32_t i = 0; i < produced; ++i)
    {
        uint64_t addr = reinterpret_cast<uint64_t>(umem_.buffer) + (static_cast<uint64_t>(idx + i) * umem_.frameSize);
        *xsk_ring_prod__fill_addr(&umem_.fill, idx + i) = addr;
    }

    xsk_ring_prod__submit(&umem_.fill, produced);
    return true;
}

void XdpDriver::releaseFrame(uint64_t frameAddr) noexcept
{
    if (!umem_.umem)
        return;

    uint32_t fillIdx = 0;
    if (xsk_ring_prod__reserve(&umem_.fill, 1, &fillIdx) == 1)
    {
        *xsk_ring_prod__fill_addr(&umem_.fill, fillIdx) = frameAddr;
        xsk_ring_prod__submit(&umem_.fill, 1);
    }
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

        uint32_t fillIdx = 0;
        if (xsk_ring_prod__reserve(&umem_.fill, 1, &fillIdx) == 1)
        {
            *xsk_ring_prod__fill_addr(&umem_.fill, fillIdx) = addr;
            xsk_ring_prod__submit(&umem_.fill, 1);
        }
    }

    xsk_ring_cons__release(&umem_.comp, completed);

    // Decrement per-socket outstanding counters. A single global counter
    // is not enough because completion is tracked per socket, but the
    // counter is only used for frame rotation in transmitPacket.
    for (auto& inst : instances_)
    {
        if (inst->socket.outstandingTx >= completed)
            inst->socket.outstandingTx -= completed;
        else
            inst->socket.outstandingTx = 0;
    }

    return true;
}

Status XdpDriver::start()
{
    if (instances_.empty())
    {
        logError("start() called before configure()");
        return Status::InvalidArgument;
    }

    resetStats();
    logInfo("XdpDriver started with %zu interface(s)", instances_.size());
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

RecvStatus XdpDriver::receivePackets(snet::layers::Packet** rawPacket, uint16_t* packetCount, uint16_t maxCount)
{
    if (!rawPacket || !packetCount || maxCount == 0)
    {
        if (packetCount)
            *packetCount = 0;
        return RecvStatus::Ok;
    }

    if (!pool_ || instances_.empty())
    {
        logError("receivePackets called before configure()");
        *packetCount = 0;
        return RecvStatus::Error;
    }

    uint16_t idx = 0;
    RecvStatus status = RecvStatus::Ok;

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

        XdpInstance* inst = nullptr;
        uint32_t rxIdx = 0;
        const size_t n = instances_.size();
        for (size_t i = 0; i < n; ++i)
        {
            const size_t cur = (currInstanceIdx_ + 1 + i) % n;

            auto peekResult = xsk_ring_cons__peek(&instances_[cur]->socket.rx, 1, &rxIdx);
            logWarning("peek on %s: result=%u", instances_[cur]->name.c_str(), peekResult);

            if (peekResult == 1)
            {
                inst = instances_[cur].get();
                currInstanceIdx_ = cur;
                break;
            }
        }

        if (!inst)
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

        const struct xdp_desc* desc = xsk_ring_cons__rx_desc(&inst->socket.rx, rxIdx);
        const uint64_t addr = desc->addr;
        const uint32_t len = desc->len;
        uint8_t* data = reinterpret_cast<uint8_t*>(addr);

        wrapper->attach(data, len, len, addr, inst);
        rawPacket[idx++] = wrapper->asPacket();

        xsk_ring_cons__release(&inst->socket.rx, 1);

        stats_.packetsReceived++;
    }

    refillFillRing(fillRingSize_ / 2);

    *packetCount = idx;
    return status;
}

RecvStatus XdpDriver::waitForPacket()
{
    std::vector<pollfd> pfds;
    pfds.reserve(instances_.size());
    for (auto& inst : instances_)
    {
        if (!inst->socket.xsk)
            continue;
        struct pollfd pfd{};
        pfd.fd = xsk_socket__fd(inst->socket.xsk);
        pfd.events = POLLIN;
        pfd.revents = 0;
        pfds.push_back(pfd);
    }

    while (true)
    {
        if (interrupted_.load(std::memory_order_acquire))
        {
            interrupted_.store(false, std::memory_order_release);
            return RecvStatus::Interrupted;
        }

        int ret = ::poll(pfds.data(), pfds.size(), 1000);
        if (ret > 0)
        {
            for (auto& p : pfds)
            {
                if (p.revents & (POLLHUP | POLLERR | POLLNVAL))
                {
                    logError("error condition on AF_XDP socket");
                    return RecvStatus::Error;
                }
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

    const bool pass = (verdict == Verdict::Pass || verdict == Verdict::Replace || verdict == Verdict::Ignore);

    XdpInstance* inst = wrapper->instance();

    if (pass && inst && inst->peer)
    {
        const uint64_t frameAddr = wrapper->frameAddr();
        const uint32_t caplen = wrapper->caplen();

        uint32_t txIdx = 0;
        if (xsk_ring_prod__reserve(&inst->peer->socket.tx, 1, &txIdx) == 1)
        {
            struct xdp_desc* desc = xsk_ring_prod__tx_desc(&inst->peer->socket.tx, txIdx);
            desc->addr = frameAddr;
            desc->len = caplen;
            xsk_ring_prod__submit(&inst->peer->socket.tx, 1);

            if (::sendto(xsk_socket__fd(inst->peer->socket.xsk), nullptr, 0, MSG_DONTWAIT, nullptr, 0) < 0)
            {
                if (errno != EAGAIN && errno != ENOBUFS)
                {
                    logError("sendto failed on %s: %s", inst->peer->name.c_str(), std::strerror(errno));
                }
            }

            // Frame goes out through the peer TX ring. It will be returned
            // to the fill ring by the kernel via the completion ring once
            // transmission completes.
            pool_->release(wrapper);
            return Status::Success;
        }

        logWarning("TX ring on %s is full, dropping packet", inst->peer->name.c_str());
    }

    // Packet was dropped or no peer is available. Return the frame to the
    // fill ring so it can be reused.
    releaseFrame(wrapper->frameAddr());
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

    if (instances_.empty())
    {
        logError("inject: no interfaces configured");
        return Status::Error;
    }

    uint32_t dstIp = 0;
    std::memcpy(&dstIp, data + 16, sizeof(dstIp));

    XdpInstance* egress = findEgress(dstIp);
    if (!egress)
        egress = instances_[0].get();

    if (!transmitPacket(*egress, data, dataLen))
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

    // Broadcast MAC is used as a placeholder. A real implementation would
    // look up the neighbour entry, for example via /proc/net/arp.
    std::memset(dstMac.bytes.data(), 0xFF, ETH_ALEN);

    layers::HeaderBuilder<layers::ethernet_header> builder(eth,
                                                           headroom,
                                                           [](size_t) noexcept
                                                           {
                                                           });
    builder.set(&layers::ethernet_header::dstMac, dstMac.bytes)
        .set(&layers::ethernet_header::srcMac, srcMac.bytes)
        .set(&layers::ethernet_header::etherType, casket::host_to_be(static_cast<uint16_t>(layers::EtherType::IP)))
        .build();

    uint32_t frameLen = ETH_HLEN + ipLen;

    if (!transmitPacket(*instances_[0], eth, frameLen))
        return Status::Error;

    stats_.packetsInjected++;
    return Status::Success;
}

bool XdpDriver::transmitPacket(XdpInstance& inst, const uint8_t* data, uint32_t len)
{
    if (!inst.socket.xsk)
        return false;

    uint32_t txIdx = 0;
    if (xsk_ring_prod__reserve(&inst.socket.tx, 1, &txIdx) != 1)
    {
        logError("TX ring on %s is full", inst.name.c_str());
        return false;
    }

    struct xdp_desc* desc = xsk_ring_prod__tx_desc(&inst.socket.tx, txIdx);

    // Simple rotating allocation of UMEM frames for TX. This path is used
    // by inject(), which operates on external buffers, not on frames that
    // already live in the UMEM.
    const uint64_t addr =
        reinterpret_cast<uint64_t>(umem_.buffer) + (inst.socket.outstandingTx % umem_.numFrames) * umem_.frameSize;

    std::memcpy(reinterpret_cast<void*>(addr), data, len);

    desc->addr = addr;
    desc->len = len;
    inst.socket.outstandingTx++;

    xsk_ring_prod__submit(&inst.socket.tx, 1);

    if (::sendto(xsk_socket__fd(inst.socket.xsk), nullptr, 0, MSG_DONTWAIT, nullptr, 0) < 0)
    {
        if (errno != EAGAIN && errno != ENOBUFS)
        {
            logError("sendto failed on %s: %s", inst.name.c_str(), std::strerror(errno));
            return false;
        }
    }

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

XdpInstance* XdpDriver::findEgress(uint32_t dstIp) const noexcept
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
    for (auto& inst : instances_)
    {
        unloadXdpProgram(*inst);
        if (inst->socket.xsk)
        {
            xsk_socket__delete(inst->socket.xsk);
            inst->socket.xsk = nullptr;
        }
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

    pool_.reset();
    instances_.clear();
    currInstanceIdx_ = 0;
}

} // namespace snet::driver

SNET_DLL_ALIAS(snet::driver::XdpDriver::create, CreateDriver)