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

bool disableOffloads(const std::string& ifname)
{
    std::string cmd = "ethtool -K " + ifname +
                      " tso off gso off gro off lro off tx off rx off 2>/dev/null";
    int rc = std::system(cmd.c_str());
    return rc == 0;
}

} // namespace

// ============================================================================
// Ctor / dtor / factory
// ============================================================================

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

// ============================================================================
// Options / configure
// ============================================================================

Status XdpDriver::declareOptions(io::Config& config)
{
    config.addDriverOption(OptionBuilder("queue_id", Value(&queueId_))
        .setDefaultValue(0u)
        .setDescription("AF_XDP queue ID (0-based)")
        .build());

    config.addDriverOption(OptionBuilder("umem_num_frames", Value(&umemNumFrames_))
        .setDefaultValue(8192u)
        .setDescription("Number of UMEM frames (power of two)")
        .build());

    config.addDriverOption(OptionBuilder("umem_frame_size", Value(&umemFrameSize_))
        .setDefaultValue(2048u)
        .setDescription("Size of each UMEM frame in bytes")
        .build());

    config.addDriverOption(OptionBuilder("fill_ring_size", Value(&fillRingSize_))
        .setDefaultValue(4096u)
        .setDescription("Fill ring size (power of two)")
        .build());

    config.addDriverOption(OptionBuilder("completion_ring_size", Value(&completionRingSize_))
        .setDefaultValue(4096u)
        .setDescription("Completion ring size (power of two)")
        .build());

    config.addDriverOption(OptionBuilder("rx_ring_size", Value(&rxRingSize_))
        .setDefaultValue(2048u)
        .setDescription("RX ring size (power of two)")
        .build());

    config.addDriverOption(OptionBuilder("tx_ring_size", Value(&txRingSize_))
        .setDefaultValue(2048u)
        .setDescription("TX ring size (power of two)")
        .build());

    config.addDriverOption(OptionBuilder("batch_size", Value(&batchSize_))
        .setDefaultValue(64u)
        .setDescription("Batch size for RX/TX processing")
        .build());

    config.addDriverOption(OptionBuilder("zero_copy", Value(&zeroCopy_))
        .setDefaultValue(false)
        .setDescription("Use zero-copy mode (requires driver support; not available in VirtualBox)")
        .build());

    config.addDriverOption(OptionBuilder("use_skb_mode", Value(&useSkbMode_))
        .setDefaultValue(true)
        .setDescription("Use SKB (generic) XDP mode instead of native")
        .build());

    config.addDriverOption(OptionBuilder("bpf_filter", Value(&bpfFilter_))
        .setDescription("BPF filter string (e.g. 'tcp port 80')")
        .build());

    config.addDriverOption(OptionBuilder("bpf_obj_path", Value(&bpfObjPath_))
        .setDefaultValue("xdp_redirect.bpf.o")
        .setDescription("Path to the compiled XDP BPF object file")
        .build());

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

    if (!isPowerOfTwo(umemNumFrames_) || !isPowerOfTwo(fillRingSize_) ||
        !isPowerOfTwo(completionRingSize_) || !isPowerOfTwo(rxRingSize_) ||
        !isPowerOfTwo(txRingSize_))
    {
        logError("ring sizes and UMEM frame count must be powers of two");
        return Status::InvalidArgument;
    }

    // FIX: batch_size must be non-zero and should not exceed ring sizes.
    if (batchSize_ == 0)
    {
        logError("batch_size must be > 0");
        return Status::InvalidArgument;
    }
    if (batchSize_ > rxRingSize_ || batchSize_ > txRingSize_ ||
        batchSize_ > completionRingSize_)
    {
        logWarning("batch_size (%u) exceeds ring sizes, clamping to %u",
                   batchSize_, completionRingSize_);
        batchSize_ = completionRingSize_;
    }

    // Reserve one quarter of UMEM frames for the TX copy path (inject).
    txPoolSize_ = umemNumFrames_ / 4;
    if (txPoolSize_ == 0)
        txPoolSize_ = 1;

    // FIX: the data-frame count handed to the fill ring must be > 0.
    if (umemNumFrames_ <= txPoolSize_)
    {
        logError("umem_num_frames (%u) is too small: must be > tx pool (%u)",
                 umemNumFrames_, txPoolSize_);
        return Status::InvalidArgument;
    }

    // ------------------------------------------------------------------
    // Discover interfaces
    // ------------------------------------------------------------------
    instances_.reserve(devices_.size());

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
            logWarning("failed to get IP/mask for '%s', continuing without IP", name.c_str());
            inst->ip = 0;
            inst->netmask = 0;
        }

        if (!getIfMac(name, inst->mac))
        {
            logError("failed to get MAC for '%s'", name.c_str());
            return Status::Error;
        }

        disableOffloads(name);  // best effort

        instances_.push_back(std::move(inst));
    }

    // Pair interfaces for transparent bridge forwarding.
    if (instances_.size() == 1)
    {
        instances_[0]->peerIdx = 0;
    }
    else
    {
        for (size_t i = 0; i + 1 < instances_.size(); i += 2)
        {
            instances_[i]->peerIdx = i + 1;
            instances_[i + 1]->peerIdx = i;
        }
        if (instances_.size() % 2)
            instances_.back()->peerIdx = static_cast<size_t>(-1);
    }

    // Detach stale XDP programs from previous runs.
    for (auto& inst : instances_)
    {
        struct xdp_multiprog* mp =
            xdp_multiprog__get_from_ifindex(static_cast<int>(inst->ifindex));
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

    // ------------------------------------------------------------------
    // UMEM and sockets
    // ------------------------------------------------------------------
    if (!setupUmem(umemNumFrames_, umemFrameSize_))
        return Status::Error;

    for (size_t i = 0; i < instances_.size(); ++i)
    {
        if (!setupSocket(*instances_[i], queueId_))
            return Status::Error;
    }

    // ------------------------------------------------------------------
    // BPF program / map per interface
    // ------------------------------------------------------------------
    for (auto& inst : instances_)
    {
        if (!loadXdpProgram(*inst))
            return Status::Error;
    }

    for (auto& inst : instances_)
    {
        if (!attachXdpProgram(*inst))
            return Status::Error;
    }

    // Register XSK fds into the per-interface XSK map.
    for (auto& inst : instances_)
    {
        uint32_t key = queueId_;
        int err = bpf_map_update_elem(inst->xskMapFd, &key, &inst->socket.xskFd, BPF_ANY);
        logInfo("XSK map insert: iface=%s fd=%d err=%d", inst->name.c_str(), inst->socket.xskFd, err);
        if (err != 0)
        {
            logError("failed to insert XSK fd into XSK map for %s: %s",
                     inst->name.c_str(), std::strerror(errno));
            return Status::Error;
        }
    }

    // ------------------------------------------------------------------
    // Packet pool
    // ------------------------------------------------------------------
    uint32_t poolSize = config.getMsgPoolSize();
    if (poolSize == 0)
    {
        poolSize = umemNumFrames_ / 10;
        if (poolSize == 0)
            poolSize = 1;
    }
    pool_ = std::make_unique<XdpPool>(poolSize);

    // ------------------------------------------------------------------
    // Fill ring: only non-TX frames are handed to the kernel for RX.
    // ------------------------------------------------------------------
    replenishFillRingFromCache();

    logInfo("XdpDriver configured: %zu interface(s), queue=%u, umem=%u x %u",
            instances_.size(), queueId_, umemNumFrames_, umem_.frameSize);

    return Status::Success;
}

// ============================================================================
// UMEM
// ============================================================================

bool XdpDriver::setupUmem(uint32_t numFrames, uint32_t frameSize)
{
    // Frame size must be page-aligned.
    long pageSize = getpagesize();
    frameSize = (frameSize + pageSize - 1) & ~(pageSize - 1);

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

    struct xsk_umem_config cfg{};
    cfg.fill_size = fillRingSize_;
    cfg.comp_size = completionRingSize_;
    cfg.frame_size = frameSize;
    cfg.frame_headroom = 0;
    cfg.flags = 0;

    int ret = xsk_umem__create(&umem_.umem, umem_.buffer, totalSize,
                               &umem_.fill, &umem_.comp, &cfg);
    if (ret != 0)
    {
        logError("xsk_umem__create failed: %s", std::strerror(-ret));
        ::munmap(umem_.buffer, totalSize);
        umem_.buffer = nullptr;
        return false;
    }

    // Pre-populate the TX frame pool with reserved frames.
    // FIX: keep the frame addresses consistent with the fill-ring frame
    // convention (offset relative to UMEM base), not absolute pointers.
    txFreeFrames_.clear();
    txFreeFrames_.reserve(txPoolSize_);
    for (uint32_t i = 0; i < txPoolSize_; ++i)
    {
        txFreeFrames_.push_back(static_cast<uint64_t>(i) * frameSize);
    }

    logInfo("UMEM created: %u frames x %u bytes = %zu MB, tx pool = %u frames",
            numFrames, frameSize, totalSize / (1024 * 1024), txPoolSize_);
    return true;
}

// ============================================================================
// Socket
// ============================================================================

bool XdpDriver::setupSocket(XdpInstance& inst, uint32_t queueId)
{
    struct xsk_socket_config cfg{};
    cfg.rx_size = rxRingSize_;
    cfg.tx_size = txRingSize_;
    cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;  // we load manually
    cfg.xdp_flags = useSkbMode_ ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;
    cfg.bind_flags = 0;

    if (zeroCopy_)
        cfg.bind_flags |= XDP_ZEROCOPY;
    else
        cfg.bind_flags |= XDP_COPY;

    int ret = xsk_socket__create_shared(&inst.socket.xsk,
                                        inst.name.c_str(),
                                        queueId,
                                        umem_.umem,
                                        &inst.socket.rx,
                                        &inst.socket.tx,
                                        &umem_.fill,
                                        &umem_.comp,
                                        &cfg);
    if (ret != 0)
    {
        logError("xsk_socket__create_shared failed on %s queue %u - %s", inst.name.c_str(), queueId,
                 std::strerror(-ret));
        return false;
    }

    // FIX: xskFd now lives in the socket struct.
    inst.socket.xskFd = xsk_socket__fd(inst.socket.xsk);
    if (inst.socket.xskFd < 0)
    {
        logError("failed to get XSK socket fd for %s", inst.name.c_str());
        return false;
    }

    logInfo("AF_XDP socket created on %s queue %u (zero-copy=%d)",
            inst.name.c_str(), queueId, zeroCopy_);
    return true;
}

// ============================================================================
// BPF program
// ============================================================================

bool XdpDriver::loadXdpProgram(XdpInstance& inst)
{
    struct bpf_object* obj = bpf_object__open_file(bpfObjPath_.c_str(), nullptr);
    if (!obj)
    {
        logError("failed to open BPF object '%s' for %s",
                 bpfObjPath_.c_str(), inst.name.c_str());
        return false;
    }

    if (bpf_object__load(obj) != 0)
    {
        logError("failed to load BPF object '%s' for %s",
                 bpfObjPath_.c_str(), inst.name.c_str());
        bpf_object__close(obj);
        return false;
    }

    struct bpf_program* prog =
        bpf_object__find_program_by_name(obj, "xdp_redirect_prog");
    if (!prog)
    {
        logError("BPF program 'xdp_redirect_prog' not found in '%s'",
                 bpfObjPath_.c_str());
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

    logInfo("BPF object loaded for %s: prog_fd=%d, map_fd=%d",
            inst.name.c_str(), inst.xdpProgFd, inst.xskMapFd);
    return true;
}

bool XdpDriver::attachXdpProgram(XdpInstance& inst)
{
    __u32 flags = useSkbMode_ ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;

    int err = bpf_xdp_attach(static_cast<int>(inst.ifindex),
                             inst.xdpProgFd, flags, nullptr);

    if (err < 0)
    {
        logError("failed to attach XDP program to %s (ifindex=%u): %s",
                 inst.name.c_str(), inst.ifindex, std::strerror(-err));
        return false;
    }

    logInfo("XDP program attached to %s (ifindex=%u, flags=0x%x)",
            inst.name.c_str(), inst.ifindex, flags);
    return true;
}

void XdpDriver::unloadXdpProgram(XdpInstance& inst) noexcept
{
    if (inst.ifindex && inst.xdpProgFd >= 0)
    {
        __u32 flags = useSkbMode_ ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;
        int err = bpf_xdp_detach(static_cast<int>(inst.ifindex), flags, nullptr);
        if (err)
            logWarning("bpf_xdp_detach failed on %s: %s",
                       inst.name.c_str(), std::strerror(-err));
    }
    if (inst.bpfObj)
    {
        bpf_object__close(inst.bpfObj);
        inst.bpfObj = nullptr;
    }
    inst.xdpProgFd = -1;
    inst.xskMapFd = -1;
}

// ============================================================================
// Rings
// ============================================================================

void XdpDriver::replenishFillRingFromCache() noexcept
{
    if (!umem_.umem)
        return;

    uint32_t dataFrames = umem_.numFrames - txPoolSize_;
    if (dataFrames == 0)
        return;

    // Ограничиваем запрос размером ring'а — reserve() не умеет частичный резерв
    uint32_t want = std::min(dataFrames, fillRingSize_);

    uint32_t idx = 0;
    uint32_t produced = xsk_ring_prod__reserve(&umem_.fill, want, &idx);
    logInfo("replenish: requested=%u, produced=%u", want, produced);
    if (produced == 0)
        return;

    for (uint32_t i = 0; i < produced; ++i)
    {
        uint64_t frameId = txPoolSize_ + i;
        *xsk_ring_prod__fill_addr(&umem_.fill, idx + i) = frameId * umem_.frameSize;
    }

    xsk_ring_prod__submit(&umem_.fill, produced);
    logInfo("Fill ring replenished with %u frames", produced);
}

void XdpDriver::processCompletionRing() noexcept
{
    if (!umem_.umem)
        return;

    uint32_t idx = 0;
    uint32_t completed = xsk_ring_cons__peek(&umem_.comp, batchSize_, &idx);
    if (completed == 0)
        return;

    // FIX: only TX-pool frames must be returned to the TX pool; RX frames
    // must be returned to the fill ring. The completion ring mixes both,
    // so we separate them by frame-id range:
    //   [0, txPoolSize_)            -> TX pool
    //   [txPoolSize_, numFrames)    -> fill ring
    // This is safe because the two ranges never overlap.
    uint32_t fillIdx = 0;
    uint32_t fillReserved = xsk_ring_prod__reserve(&umem_.fill, completed, &fillIdx);

    uint32_t toFill = 0;
    uint32_t toTxPool = 0;

    for (uint32_t i = 0; i < completed; ++i)
    {
        uint64_t addr = *xsk_ring_cons__comp_addr(&umem_.comp, idx + i);
        uint64_t frameId = addr / umem_.frameSize;

        if (frameId < txPoolSize_)
        {
            // TX-pool frame: give it back to the user-space TX pool.
            txFreeFrames_.push_back(addr);
            ++toTxPool;
        }
        else if (toFill < fillReserved)
        {
            *xsk_ring_prod__fill_addr(&umem_.fill, fillIdx + toFill) = addr;
            ++toFill;
        }
        else
        {
            // Fill ring is full; this RX frame is lost. Increase
            // fill_ring_size or drain faster to avoid.
            ++toTxPool;  // counted as "not returned to fill"
        }
    }

    if (toFill > 0)
        xsk_ring_prod__submit(&umem_.fill, toFill);

    xsk_ring_cons__release(&umem_.comp, completed);

    if (toFill < (completed - toTxPool))
    {
        logWarning("completion ring: %u frames lost (fill ring full)",
                   (completed - toTxPool) - toFill);
    }
}

uint64_t XdpDriver::allocTxFrame() noexcept
{
    if (txFreeFrames_.empty())
        return UINT64_MAX;
    uint64_t addr = txFreeFrames_.back();
    txFreeFrames_.pop_back();
    return addr;
}

void XdpDriver::freeTxFrame(uint64_t frameAddr) noexcept
{
    // FIX: guard against double-free in the TX pool.
    for (uint64_t f : txFreeFrames_)
    {
        if (f == frameAddr)
        {
            logWarning("double free of TX frame 0x%llx",
                       static_cast<unsigned long long>(frameAddr));
            return;
        }
    }
    txFreeFrames_.push_back(frameAddr);
}

// ============================================================================
// Receive / forward
// ============================================================================

RecvStatus XdpDriver::receivePackets(layers::Packet** rawPacket,
                                     uint16_t* packetCount,
                                     uint16_t maxCount)
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

    if (interrupted_.load(std::memory_order_acquire))
    {
        interrupted_.store(false, std::memory_order_release);
        *packetCount = 0;
        return RecvStatus::Interrupted;
    }

    // Recycle completed TX frames first.
    processCompletionRing();

    uint16_t total = 0;
    RecvStatus status = RecvStatus::Ok;

    // Round-robin over all RX rings.
    while (total < maxCount)
    {
        bool gotAny = false;

        for (size_t i = 0; i < instances_.size() && total < maxCount; ++i)
        {
            const size_t cur = (currInstanceIdx_ + i) % instances_.size();
            XdpInstance& inst = *instances_[cur];

            uint32_t rxIdx = 0;
            uint32_t budget = static_cast<uint32_t>(maxCount - total);
            uint32_t avail = xsk_ring_cons__peek(&inst.socket.rx, budget, &rxIdx);
            logInfo("rx peek: iface=%s avail=%u", inst.name.c_str(), avail);
            if (avail == 0)
                continue;

            gotAny = true;
            currInstanceIdx_ = cur;

            uint32_t consumed = 0;
            for (uint32_t k = 0; k < avail && total < maxCount; ++k)
            {
                XdpWrapper* wrapper = pool_->acquire();
                if (!wrapper)
                {
                    // FIX: release only the descriptors actually consumed.
                    xsk_ring_cons__release(&inst.socket.rx, consumed);
                    status = RecvStatus::NoBuffer;
                    goto done;
                }

                const struct xdp_desc* desc =
                    xsk_ring_cons__rx_desc(&inst.socket.rx, rxIdx + k);

                // FIX: desc->addr is a frame offset relative to UMEM base;
                // keep it as the frame handle, and use it to compute the
                // data pointer through the standard AF_XDP helpers.
                const uint64_t frameAddr = desc->addr;
                const uint32_t len = desc->len;

                uint8_t* data = static_cast<uint8_t*>(
                    xsk_umem__get_data(umem_.buffer, frameAddr));

                wrapper->attach(data, len, len, frameAddr, &inst);
                rawPacket[total++] = wrapper->asPacket();
                ++consumed;
                stats_.packetsReceived++;
            }

            // FIX: release exactly the number of descriptors we consumed.
            xsk_ring_cons__release(&inst.socket.rx, consumed);
        }

        if (!gotAny)
        {
            if (total == 0)
            {
                pollForEvents(100);
                if (interrupted_.load(std::memory_order_acquire))
                {
                    interrupted_.store(false, std::memory_order_release);
                    status = RecvStatus::Interrupted;
                }
                else
                {
                    status = RecvStatus::WouldBlock;
                }
            }
            break;
        }
    }

done:
    processCompletionRing();

    *packetCount = total;
    return status;
}

void XdpDriver::pollForEvents(int timeoutMs) noexcept
{
    struct pollfd pfds[64];
    nfds_t nfds = 0;

    for (auto& inst : instances_)
    {
        if (!inst->socket.xsk || nfds >= 64)
            continue;
        pfds[nfds].fd = xsk_socket__fd(inst->socket.xsk);
        pfds[nfds].events = POLLIN;
        pfds[nfds].revents = 0;
        ++nfds;
    }

    if (nfds == 0)
        return;

    int ret;
    do
    {
        ret = ::poll(pfds, nfds, timeoutMs);
    } while (ret < 0 && errno == EINTR);
}

// ============================================================================
// Transmit / forward
// ============================================================================

bool XdpDriver::forwardFrame(XdpInstance& egress,
                             uint64_t frameAddr,
                             uint32_t len) noexcept
{
    uint32_t txIdx = 0;
    if (xsk_ring_prod__reserve(&egress.socket.tx, 1, &txIdx) != 1)
        return false;

    struct xdp_desc* desc = xsk_ring_prod__tx_desc(&egress.socket.tx, txIdx);
    desc->addr = frameAddr;
    desc->len = len;
    xsk_ring_prod__submit(&egress.socket.tx, 1);

    if (xsk_ring_prod__needs_wakeup(&egress.socket.tx))
    {
        int rc = ::sendto(xsk_socket__fd(egress.socket.xsk), nullptr, 0,
                          MSG_DONTWAIT, nullptr, 0);
        if (rc < 0 && errno != EAGAIN && errno != ENOBUFS && errno != ENETDOWN)
        {
            logWarning("sendto (forward) failed on %s: %s",
                       egress.name.c_str(), std::strerror(errno));
        }
    }
    return true;
}

bool XdpDriver::transmitCopy(XdpInstance& egress,
                             const uint8_t* data,
                             uint32_t len) noexcept
{
    if (len > umem_.frameSize)
        return false;

    uint64_t frameAddr = allocTxFrame();
    if (frameAddr == UINT64_MAX)
    {
        logWarning("TX frame pool exhausted on %s", egress.name.c_str());
        return false;
    }

    void* dst = xsk_umem__get_data(umem_.buffer, frameAddr);
    std::memcpy(dst, data, len);

    uint32_t txIdx = 0;
    if (xsk_ring_prod__reserve(&egress.socket.tx, 1, &txIdx) != 1)
    {
        freeTxFrame(frameAddr);
        return false;
    }

    struct xdp_desc* desc = xsk_ring_prod__tx_desc(&egress.socket.tx, txIdx);
    desc->addr = frameAddr;
    desc->len = len;
    xsk_ring_prod__submit(&egress.socket.tx, 1);

    // NOTE: TX-pool frames are returned to the pool by processCompletionRing()
    // once the kernel signals that the transmission completed. Do NOT push
    // the frame back into the pool here — the kernel still owns it until
    // the completion entry arrives.

    if (xsk_ring_prod__needs_wakeup(&egress.socket.tx))
    {
        int rc = ::sendto(xsk_socket__fd(egress.socket.xsk), nullptr, 0,
                          MSG_DONTWAIT, nullptr, 0);
        if (rc < 0 && errno != EAGAIN && errno != ENOBUFS)
        {
            logWarning("sendto (inject) failed on %s: %s",
                       egress.name.c_str(), std::strerror(errno));
        }
    }
    return true;
}

XdpInstance* XdpDriver::peerOf(const XdpInstance& inst) const noexcept
{
    if (inst.peerIdx == static_cast<size_t>(-1))
        return nullptr;
    if (inst.peerIdx >= instances_.size())
        return nullptr;
    return instances_[inst.peerIdx].get();
}

XdpInstance* XdpDriver::findEgressByIp(uint32_t dstIp) const noexcept
{
    for (const auto& inst : instances_)
    {
        if (!inst->hasIp())
            continue;
        if ((dstIp & inst->netmask) == (inst->ip & inst->netmask))
            return inst.get();
    }
    return nullptr;
}

// ============================================================================
// Finalize
// ============================================================================

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

    XdpInstance* inst = wrapper->instance();
    const uint64_t frameAddr = wrapper->frameAddr();
    const uint32_t caplen = wrapper->caplen();

    const bool forward =
        (verdict == Verdict::Pass || verdict == Verdict::Replace);

    if (forward && inst)
    {
        XdpInstance* egress = peerOf(*inst);
        if (egress && forwardFrame(*egress, frameAddr, caplen))
        {
            // Frame will be returned to the fill ring by the kernel
            // via the completion ring after transmission completes.
            pool_->release(wrapper);
            return Status::Success;
        }
        logWarning("forward failed on %s (peer %s)",
                   inst->name.c_str(),
                   egress ? egress->name.c_str() : "<none>");
    }

    // Drop / Ignore / forward failure: recycle the frame explicitly.
    uint32_t fillIdx = 0;
    if (xsk_ring_prod__reserve(&umem_.fill, 1, &fillIdx) == 1)
    {
        *xsk_ring_prod__fill_addr(&umem_.fill, fillIdx) = frameAddr;
        xsk_ring_prod__submit(&umem_.fill, 1);
    }
    pool_->release(wrapper);

    logInfo("finalize: verdict=%d inst=%s frameAddr=%llu caplen=%u",
        static_cast<int>(verdict),
        inst ? inst->name.c_str() : "<null>",
        static_cast<unsigned long long>(frameAddr), caplen);
    return Status::Success;
}

// ============================================================================
// Inject
// ============================================================================

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

    XdpInstance* egress = findEgressByIp(dstIp);
    if (!egress)
        egress = instances_[0].get();

    // FIX: allocate the frame from the UMEM directly instead of using a
    // fixed 2 KiB stack buffer, so the length is bounded by the frame size.
    if (dataLen + ETH_HLEN > umem_.frameSize)
    {
        logError("inject: packet too large (%u > %llu)",
                 dataLen + ETH_HLEN,
                 static_cast<unsigned long long>(umem_.frameSize));
        return Status::InvalidArgument;
    }

    uint64_t frameAddr = allocTxFrame();
    if (frameAddr == UINT64_MAX)
    {
        logWarning("inject: TX frame pool exhausted");
        return Status::Error;
    }

    uint8_t* frame = static_cast<uint8_t*>(
        xsk_umem__get_data(umem_.buffer, frameAddr));

    std::memcpy(frame + ETH_HLEN, data, dataLen);

    auto* eth = reinterpret_cast<struct ethhdr*>(frame);
    std::memcpy(eth->h_source, egress->mac.bytes.data(), ETH_ALEN);
    std::memset(eth->h_dest, 0xFF, ETH_ALEN);  // broadcast placeholder
    eth->h_proto = htons(ETH_P_IP);

    uint32_t frameLen = ETH_HLEN + dataLen;

    // transmitCopy() will allocate its own frame; instead, submit directly.
    uint32_t txIdx = 0;
    if (xsk_ring_prod__reserve(&egress->socket.tx, 1, &txIdx) != 1)
    {
        freeTxFrame(frameAddr);
        return Status::Error;
    }

    struct xdp_desc* desc = xsk_ring_prod__tx_desc(&egress->socket.tx, txIdx);
    desc->addr = frameAddr;
    desc->len = frameLen;
    xsk_ring_prod__submit(&egress->socket.tx, 1);

    if (xsk_ring_prod__needs_wakeup(&egress->socket.tx))
    {
        int rc = ::sendto(xsk_socket__fd(egress->socket.xsk), nullptr, 0,
                          MSG_DONTWAIT, nullptr, 0);
        if (rc < 0 && errno != EAGAIN && errno != ENOBUFS)
        {
            logWarning("sendto (inject) failed on %s: %s",
                       egress->name.c_str(), std::strerror(errno));
        }
    }

    stats_.packetsInjected++;
    return Status::Success;
}

Status XdpDriver::injectPacket(layers::Packet* rawPacket)
{
    if (!rawPacket)
        return Status::InvalidArgument;

    const uint8_t* data = rawPacket->getData();
    uint32_t len = static_cast<uint32_t>(rawPacket->getDataLen());

    if (len < ETH_HLEN)
        return Status::InvalidArgument;

    if (instances_.empty())
        return Status::Error;

    if (!transmitCopy(*instances_[0], data, len))
        return Status::Error;

    stats_.packetsInjected++;
    return Status::Success;
}

// ============================================================================
// Stats / misc
// ============================================================================

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

// ============================================================================
// Start / stop / interrupt
// ============================================================================

Status XdpDriver::start()
{
    if (instances_.empty())
    {
        logError("start() called before configure()");
        return Status::InvalidArgument;
    }

    resetStats();
    interrupted_.store(false, std::memory_order_release);
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

// ============================================================================
// Cleanup
// ============================================================================

void XdpDriver::cleanup() noexcept
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

    txFreeFrames_.clear();
    txPoolSize_ = 0;
    pool_.reset();
    instances_.clear();
    currInstanceIdx_ = 0;
}

} // namespace snet::driver

SNET_DLL_ALIAS(snet::driver::XdpDriver::create, CreateDriver)