#include "xdp_driver.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <stdexcept>

#include <arpa/inet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <casket/log/log.hpp>
#include <casket/opt/opt.hpp>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

using namespace casket::opt;
using namespace snet::io;

namespace snet::driver
{

namespace
{

/// ETH_ALEN
constexpr uint32_t kMacLen = 6;

inline void swapMacAddresses(uint8_t* pkt) noexcept
{
    for (uint32_t i = 0; i < kMacLen; ++i)
        std::swap(pkt[i], pkt[i + kMacLen]);
}

inline std::string trimCopy(std::string_view s)
{
    size_t b = 0;
    size_t e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b])))
        ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1])))
        --e;
    return std::string{s.substr(b, e - b)};
}

} // namespace

XdpDriver::XdpDriver(const io::DriverSpec& config)
    : DriverBase(config)
{
}

XdpDriver::~XdpDriver() noexcept
{
    stop();
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
    config.addDriverOption(OptionBuilder("bpf_object", Value(&bpfObject_))
        .setDescription("Path to compiled XDP BPF object file (required)")
        .build());
    config.addDriverOption(OptionBuilder("bpf_section", Value(&bpfSection_))
        .setDefaultValue(std::string{"xdp"})
        .setDescription("BPF program section name")
        .build());
    config.addDriverOption(OptionBuilder("zero_copy", Value(&zeroCopy_))
        .setDefaultValue(true)
        .setDescription("Use XDP_MODE_NATIVE (zero-copy) when supported")
        .build());
    config.addDriverOption(OptionBuilder("need_wakeup", Value(&needWakeup_))
        .setDefaultValue(true)
        .setDescription("Enable XDP_USE_NEED_WAKEUP")
        .build());
    config.addDriverOption(OptionBuilder("num_frames", Value(&numFrames_))
        .setDefaultValue(xdp::kDefaultNumFrames)
        .setDescription("Total number of frames in the shared UMEM")
        .build());
    config.addDriverOption(OptionBuilder("frame_size", Value(&frameSize_))
        .setDefaultValue(xdp::kDefaultFrameSize)
        .setDescription("UMEM frame size in bytes")
        .build());
    config.addDriverOption(OptionBuilder("frame_headroom", Value(&headroom_))
        .setDefaultValue(xdp::kDefaultHeadroom)
        .setDescription("Bytes reserved before packet data in each frame")
        .build());
    config.addDriverOption(OptionBuilder("fill_size", Value(&fillSize_))
        .setDefaultValue(xdp::kDefaultFillSize)
        .setDescription("FQ ring size (per socket)")
        .build());
    config.addDriverOption(OptionBuilder("comp_size", Value(&compSize_))
        .setDefaultValue(xdp::kDefaultCompSize)
        .setDescription("CQ ring size (per socket)")
        .build());
    config.addDriverOption(OptionBuilder("rx_size", Value(&rxSize_))
        .setDefaultValue(xdp::kDefaultRxSize)
        .setDescription("RX ring size (per socket)")
        .build());
    config.addDriverOption(OptionBuilder("tx_size", Value(&txSize_))
        .setDefaultValue(xdp::kDefaultTxSize)
        .setDescription("TX ring size (per socket)")
        .build());
    config.addDriverOption(OptionBuilder("batch_size", Value(&batchSize_))
        .setDefaultValue(xdp::kDefaultBatchSize)
        .setDescription("Max packets per receivePackets() call")
        .build());
    config.addDriverOption(OptionBuilder("topology", Value(&topologyStr_))
        .setDefaultValue(std::string{"pairs"})
        .setDescription("Forwarding topology: pairs|ring|single")
        .build());
    config.addDriverOption(OptionBuilder("swap_mac", Value(&swapMac_))
        .setDefaultValue(false)
        .setDescription("Swap src/dst MAC before forwarding")
        .build());
    // clang-format on
    return Status::Success;
}

Status XdpDriver::parseEndpoints(const std::string& input)
{
    endpoints_.clear();

    if (input.empty())
    {
        logError("XdpDriver: empty input");
        return Status::InvalidArgument;
    }

    size_t pos = 0;
    while (pos < input.size())
    {
        size_t comma = input.find(',', pos);
        if (comma == std::string::npos)
            comma = input.size();

        std::string tok = trimCopy(std::string_view{input}.substr(pos, comma - pos));
        if (!tok.empty())
        {
            Endpoint ep;
            const size_t colon = tok.find(':');
            if (colon == std::string::npos)
            {
                ep.iface = tok;
                ep.queue = 0;
            }
            else
            {
                ep.iface = trimCopy(std::string_view{tok}.substr(0, colon));
                const std::string qstr = trimCopy(std::string_view{tok}.substr(colon + 1));
                if (qstr.empty())
                {
                    logError("XdpDriver: empty queue in '%s'", tok.c_str());
                    return Status::InvalidArgument;
                }
                try
                {
                    unsigned long v = std::stoul(qstr, nullptr, 10);
                    if (v >= xdp::kMaxQueuesPerIface)
                        throw std::out_of_range("queue");
                    ep.queue = static_cast<uint32_t>(v);
                }
                catch (const std::exception& e)
                {
                    logError("XdpDriver: bad queue '%s': %s", qstr.c_str(), e.what());
                    return Status::InvalidArgument;
                }
            }

            if (ep.iface.empty() || ep.iface.size() >= IFNAMSIZ)
            {
                logError("XdpDriver: bad iface name '%s'", ep.iface.c_str());
                return Status::InvalidArgument;
            }

            endpoints_.push_back(std::move(ep));
        }
        pos = comma + 1;
    }

    if (endpoints_.empty())
    {
        logError("XdpDriver: no endpoints in '%s'", input.c_str());
        return Status::InvalidArgument;
    }
    if (endpoints_.size() > xdp::kMaxEndpoints)
    {
        logError("XdpDriver: too many endpoints (%zu > %u)", endpoints_.size(), xdp::kMaxEndpoints);
        return Status::InvalidArgument;
    }
    return Status::Success;
}

Status XdpDriver::parseTopology()
{
    if (topologyStr_ == "pairs")
        topology_ = ForwardTopology::Pairs;
    else if (topologyStr_ == "ring")
        topology_ = ForwardTopology::Ring;
    else if (topologyStr_ == "single")
        topology_ = ForwardTopology::Single;
    else
    {
        logError("XdpDriver: unknown topology '%s' (pairs|ring|single)", topologyStr_.c_str());
        return Status::InvalidArgument;
    }
    return Status::Success;
}

Status XdpDriver::configure(const snet::io::Config& config)
{
    snaplen_ = static_cast<size_t>(config.getSnaplen());
    timeoutMs_ = config.getTimeout();
    if (timeoutMs_ == 0)
        timeoutMs_ = -1;

    if (auto st = parseEndpoints(config.getInput()); st != Status::Success)
        return st;

    if (auto st = parseTopology(); st != Status::Success)
        return st;

    if (bpfObject_.empty())
    {
        logError("XdpDriver: 'bpf_object' is required");
        return Status::InvalidArgument;
    }

    if (frameSize_ < headroom_ + snaplen_)
    {
        logError("XdpDriver: frame_size (%u) < frame_headroom + snaplen (%zu)", frameSize_, headroom_ + snaplen_);
        return Status::InvalidArgument;
    }
    if (numFrames_ < fillSize_ + rxSize_)
    {
        logError("XdpDriver: num_frames (%u) must be >= fill_size + rx_size (%u)", numFrames_, fillSize_ + rxSize_);
        return Status::InvalidArgument;
    }

    // --- group endpoints by iface ---
    for (const auto& ep : endpoints_)
    {
        const bool known = std::any_of(ifaces_.begin(),
                                       ifaces_.end(),
                                       [&](const auto& p)
                                       {
                                           return p->iface == ep.iface;
                                       });
        if (known)
            continue;

        auto ctx = std::make_unique<IfaceContext>();
        ctx->iface = ep.iface;
        ctx->ifindex = ::if_nametoindex(ep.iface.c_str());
        if (!ctx->ifindex)
        {
            logError("XdpDriver: if_nametoindex(%s): %s", ep.iface.c_str(), std::strerror(errno));
            return Status::NoSuchDevice;
        }
        ifaces_.push_back(std::move(ctx));
    }

    // --- create one instance per endpoint ---
    for (const auto& ep : endpoints_)
    {
        auto inst = std::make_unique<XdpInstance>(*this);
        if (!inst->create(ep.iface, ep.queue))
            return Status::NoSuchDevice;

        auto it = std::find_if(ifaces_.begin(),
                               ifaces_.end(),
                               [&](const auto& p)
                               {
                                   return p->iface == ep.iface;
                               });
        (*it)->instances.push_back(inst.get());

        instancesOwned_.push_back(std::move(inst));
    }

    instances_.reserve(instancesOwned_.size());
    for (auto& p : instancesOwned_)
        instances_.push_back(p.get());

    // --- peers ---
    buildPeers();

    // --- wrapper pool ---
    uint32_t poolSize = config.getMsgPoolSize();
    if (poolSize == 0)
        poolSize = std::min<uint32_t>(numFrames_, xdp::kDefaultMsgPoolSize);

    pool_ = std::make_unique<XdpPool>(poolSize);

    logInfo(
        "XdpDriver: configured %zu iface(s), %zu endpoint(s), pool=%u", ifaces_.size(), instances_.size(), poolSize);
    return Status::Success;
}

void XdpDriver::buildPeers()
{
    const size_t n = instances_.size();
    if (n == 0)
        return;

    if (topology_ == ForwardTopology::Single)
    {
        for (auto* inst : instances_)
            inst->peer = inst;
        return;
    }

    if (topology_ == ForwardTopology::Ring)
    {
        for (size_t i = 0; i < n; ++i)
            instances_[i]->peer = instances_[(i + 1) % n];
        return;
    }

    // Pairs
    if (n == 1)
    {
        instances_[0]->peer = instances_[0];
        return;
    }
    for (size_t i = 0; i + 1 < n; i += 2)
    {
        instances_[i]->peer = instances_[i + 1];
        instances_[i + 1]->peer = instances_[i];
    }
    if (n % 2)
        instances_.back()->peer = instances_.back();
}

Status XdpDriver::start()
{
    if (instances_.empty())
    {
        logError("XdpDriver: start() called before configure()");
        return Status::InvalidArgument;
    }

    if (!setupRlimit())
        return Status::Error;

    if (!createUmem())
        return Status::Error;

    // Attach one BPF program per iface.
    for (auto& ctx : ifaces_)
    {
        if (!openBpfForIface(*ctx))
        {
            stop();
            return Status::Error;
        }
    }

    // Create AF_XDP sockets and register them in the per-iface XSKMAP.
    struct xsk_socket_config cfg{};
    cfg.rx_size = rxSize_;
    cfg.tx_size = txSize_;
    cfg.libbpf_flags = 0;
    cfg.xdp_flags = zeroCopy_ ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
    cfg.bind_flags = needWakeup_ ? XDP_USE_NEED_WAKEUP : 0;

    for (auto& ctx : ifaces_)
    {
        for (XdpInstance* inst : ctx->instances)
        {
            if (!inst->bindTo(umem_, cfg))
            {
                stop();
                return Status::Error;
            }

            int fd = inst->fd();
            uint32_t key = inst->queueId();
            if (::bpf_map_update_elem(ctx->xskmapFd, &key, &fd, BPF_ANY))
            {
                logError("XdpDriver: XSKMAP update(iface=%s q=%u): %s", ctx->iface.c_str(), key, std::strerror(errno));
                stop();
                return Status::Error;
            }

            inst->setActive(true);
        }
    }

    // Prime FQ for every endpoint.
    for (auto* inst : instances_)
        refillFq(*inst, fillSize_);

    resetStats();

    logInfo("XdpDriver: started %zu endpoint(s) on %zu iface(s)", instances_.size(), ifaces_.size());
    return Status::Success;
}

Status XdpDriver::stop()
{
    for (auto& inst : instancesOwned_)
    {
        if (inst)
            inst->destroy();
    }

    for (auto& ctx : ifaces_)
        closeBpfForIface(*ctx);

    destroyUmem();
    clearAll();
    return Status::Success;
}

void XdpDriver::clearAll()
{
    instances_.clear();
    instancesOwned_.clear();
    ifaces_.clear();
    pool_.reset();
    {
        std::lock_guard<std::mutex> lk(poolMutex_);
        freeFrames_.clear();
    }
    currInstanceIdx_ = 0;
}

Status XdpDriver::interrupt()
{
    interrupted_.store(true, std::memory_order_release);
    return Status::Success;
}

bool XdpDriver::setupRlimit()
{
    struct rlimit r{RLIM_INFINITY, RLIM_INFINITY};
    if (::setrlimit(RLIMIT_MEMLOCK, &r) && errno != EPERM)
    {
        logError("XdpDriver: setrlimit(RLIMIT_MEMLOCK): %s", std::strerror(errno));
        return false;
    }
    return true;
}

bool XdpDriver::createUmem()
{
    umemAreaSize_ = static_cast<size_t>(numFrames_) * frameSize_;
    umemArea_ = ::mmap(nullptr, umemAreaSize_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (umemArea_ == MAP_FAILED)
    {
        umemArea_ = nullptr;
        logError("XdpDriver: mmap(%zu): %s", umemAreaSize_, std::strerror(errno));
        return false;
    }

    struct xsk_umem_config umemCfg{};
    umemCfg.fill_size = fillSize_;
    umemCfg.comp_size = compSize_;
    umemCfg.frame_size = frameSize_;
    umemCfg.frame_headroom = headroom_;
    umemCfg.flags = 0;

    if (::xsk_umem__create(&umem_, umemArea_, umemAreaSize_, &umemFq_, &umemCq_, &umemCfg))
    {
        logError("XdpDriver: xsk_umem__create: %s", std::strerror(errno));
        ::munmap(umemArea_, umemAreaSize_);
        umemArea_ = nullptr;
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(poolMutex_);
        freeFrames_.clear();
        freeFrames_.reserve(numFrames_);
        for (uint32_t i = 0; i < numFrames_; ++i)
            freeFrames_.push_back(static_cast<uint64_t>(i) * frameSize_);
    }

    logInfo("XdpDriver: UMEM created (%u frames x %u B, headroom=%u)", numFrames_, frameSize_, headroom_);
    return true;
}

void XdpDriver::destroyUmem() noexcept
{
    if (umem_)
    {
        ::xsk_umem__delete(umem_);
        umem_ = nullptr;
    }
    if (umemArea_)
    {
        ::munmap(umemArea_, umemAreaSize_);
        umemArea_ = nullptr;
    }
}

bool XdpDriver::openBpfForIface(IfaceContext& ctx)
{
    ctx.program = ::xdp_program__open_file(bpfObject_.c_str(), bpfSection_.c_str(), nullptr);
    if (!ctx.program)
    {
        logError("XdpDriver: xdp_program__open_file returned NULL for %s", ctx.iface.c_str());
        return false;
    }

    long err = ::libbpf_get_error(ctx.program);
    if (err)
    {
        ctx.program = nullptr;
        logError("XdpDriver: open_file(%s, %s) for %s: %s",
                 bpfObject_.c_str(),
                 bpfSection_.c_str(),
                 ctx.iface.c_str(),
                 std::strerror(-err));
        return false;
    }

    const enum xdp_attach_mode mode = zeroCopy_ ? XDP_MODE_NATIVE : XDP_MODE_SKB;

    if (::xdp_program__attach(ctx.program, static_cast<int>(ctx.ifindex), mode, 0))
    {
        logError("XdpDriver: xdp_program__attach on %s: %s", ctx.iface.c_str(), std::strerror(errno));
        return false;
    }

    struct bpf_object* obj = ::xdp_program__bpf_obj(ctx.program);
    ctx.xskmapFd = ::bpf_object__find_map_fd_by_name(obj, "xsks_map");
    if (ctx.xskmapFd < 0)
    {
        logError("XdpDriver: map 'xsks_map' not found for %s", ctx.iface.c_str());
        return false;
    }
    return true;
}

void XdpDriver::closeBpfForIface(IfaceContext& ctx) noexcept
{
    if (ctx.program)
    {
        const enum xdp_attach_mode mode = zeroCopy_ ? XDP_MODE_NATIVE : XDP_MODE_SKB;
        ::xdp_program__detach(ctx.program, static_cast<int>(ctx.ifindex), mode, 0);
        ::xdp_program__close(ctx.program);
        ctx.program = nullptr;
    }
    ctx.xskmapFd = -1;
}

uint64_t XdpDriver::acquireFrame()
{
    std::lock_guard<std::mutex> lk(poolMutex_);
    if (freeFrames_.empty())
        return UINT64_MAX;
    uint64_t a = freeFrames_.back();
    freeFrames_.pop_back();
    return a;
}

void XdpDriver::releaseFrame(uint64_t addr)
{
    std::lock_guard<std::mutex> lk(poolMutex_);
    freeFrames_.push_back(addr);
}

uint32_t XdpDriver::refillFq(XdpInstance& inst, uint32_t max)
{
    struct xsk_ring_prod* fq = inst.fqRing();
    uint32_t produced = 0;

    while (produced < max)
    {
        uint32_t availFrames = 0;
        {
            std::lock_guard<std::mutex> lk(poolMutex_);
            availFrames = static_cast<uint32_t>(freeFrames_.size());
        }
        if (availFrames == 0)
            break;

        const uint32_t want = std::min(max - produced, availFrames);

        uint32_t idx = 0;
        const uint32_t space = ::xsk_ring_prod__reserve(fq, want, &idx);
        if (space == 0)
            break;

        uint32_t filled = 0;
        for (uint32_t i = 0; i < space; ++i)
        {
            uint64_t addr = acquireFrame();
            if (addr == UINT64_MAX)
                break;
            *::xsk_ring_prod__fill_addr(fq, idx + i) = addr;
            ++filled;
        }

        if (filled == 0)
            break;

        ::xsk_ring_prod__submit(fq, filled);
        produced += filled;

        if (filled < space)
            break;
    }
    return produced;
}

uint32_t XdpDriver::processCq(XdpInstance& inst, uint32_t max)
{
    struct xsk_ring_cons* cq = inst.cqRing();
    uint32_t idx = 0;
    const uint32_t n = ::xsk_ring_cons__peek(cq, max, &idx);
    if (!n)
        return 0;

    for (uint32_t i = 0; i < n; ++i)
    {
        const uint64_t addr = *::xsk_ring_cons__comp_addr(cq, idx + i);
        releaseFrame(addr);
    }
    ::xsk_ring_cons__release(cq, n);
    return n;
}

bool XdpDriver::kickTx(XdpInstance& inst)
{
    if (::xsk_ring_prod__needs_wakeup(inst.txRing()))
    {
        if (::sendto(inst.fd(), nullptr, 0, MSG_DONTWAIT, nullptr, 0) < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
            errno != ENETDOWN)
        {
            return false;
        }
    }
    return true;
}

void XdpDriver::swapMacInPlace(uint64_t frameAddr, uint32_t len) noexcept
{
    if (len < 2 * kMacLen)
        return;
    uint8_t* pkt = static_cast<uint8_t*>(umemArea_) + frameAddr + headroom_;
    swapMacAddresses(pkt);
}

bool XdpDriver::transmitFrame(XdpInstance* egress, uint64_t frameAddr, uint32_t len)
{
    if (!egress || !egress->active())
        return false;

    for (;;)
    {
        uint32_t idx = 0;
        if (::xsk_ring_prod__reserve(egress->txRing(), 1, &idx) == 1)
        {
            struct xdp_desc* d = ::xsk_ring_prod__tx_desc(egress->txRing(), idx);
            d->addr = frameAddr;
            d->len = len;
            ::xsk_ring_prod__submit(egress->txRing(), 1);
            kickTx(*egress);
            ++packetsSentCounter_;
            return true;
        }

        // TX full — try to reclaim completions.
        processCq(*egress, compSize_);

        if (::xsk_ring_prod__needs_wakeup(egress->txRing()))
            ::sendto(egress->fd(), nullptr, 0, MSG_DONTWAIT, nullptr, 0);

        break;
    }

    logWarning("XdpDriver: TX ring full on %s q=%u", egress->name().c_str(), egress->queueId());
    return false;
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
        logError("XdpDriver: receivePackets called before start()");
        *packetCount = 0;
        return RecvStatus::Error;
    }

    if (interrupted_.load(std::memory_order_acquire))
    {
        interrupted_.store(false, std::memory_order_release);
        *packetCount = 0;
        return RecvStatus::Interrupted;
    }

    // Reclaim completions + refill FQ for every endpoint.
    for (auto* inst : instances_)
    {
        processCq(*inst, compSize_);
        refillFq(*inst, fillSize_ / 2);
    }

    uint16_t idx = 0;
    RecvStatus status = RecvStatus::Ok;
    const uint16_t budget = std::min<uint16_t>(maxCount, static_cast<uint16_t>(batchSize_));

    const size_t nInst = instances_.size();
    for (size_t tried = 0; tried < nInst && idx < budget; ++tried)
    {
        const size_t i = (currInstanceIdx_ + tried) % nInst;
        XdpInstance* inst = instances_[i];
        if (!inst->active())
            continue;

        uint32_t pos = 0;
        const uint32_t n = ::xsk_ring_cons__peek(inst->rxRing(), budget - idx, &pos);
        if (!n)
            continue;

        for (uint32_t k = 0; k < n && idx < budget; ++k)
        {
            const struct xdp_desc* d = ::xsk_ring_cons__rx_desc(inst->rxRing(), pos + k);

            XdpWrapper* wrapper = pool_->acquire();
            if (!wrapper)
            {
                ::xsk_ring_cons__release(inst->rxRing(), n);
                if (idx == 0)
                    status = RecvStatus::NoBuffer;
                goto done;
            }

            uint8_t* data = static_cast<uint8_t*>(umemArea_) + d->addr + headroom_;
            const uint32_t cap = d->len;

            wrapper->attach(data, cap, cap, inst, d->addr);
            rawPacket[idx++] = wrapper->asPacket();
            stats_.packetsReceived++;
        }

        ::xsk_ring_cons__release(inst->rxRing(), n);
        currInstanceIdx_ = (i + 1) % nInst;
    }

    if (idx == 0)
    {
        if (timeoutMs_ != 0)
        {
            std::vector<pollfd> pfds;
            pfds.reserve(instances_.size());
            for (auto* inst : instances_)
                if (inst->active())
                    pfds.push_back({inst->fd(), POLLIN, 0});

            if (!pfds.empty())
            {
                const int ret = ::poll(pfds.data(), pfds.size(), timeoutMs_);
                if (ret > 0)
                    status = RecvStatus::Ok;
                else if (ret == 0)
                    status = RecvStatus::Timeout;
                else if (errno != EINTR)
                    status = RecvStatus::Error;
            }
        }
        else
        {
            status = RecvStatus::WouldBlock;
        }
    }

done:
    *packetCount = idx;
    return status;
}

Status XdpDriver::finalizePacket(snet::layers::Packet* rawPacket, Verdict verdict)
{
    if (!rawPacket)
    {
        logError("XdpDriver: finalizePacket(nullptr)");
        return Status::InvalidArgument;
    }

    XdpWrapper* wrapper = XdpWrapper::fromPacket(rawPacket);
    if (!wrapper || !wrapper->instance())
    {
        logError("XdpDriver: finalizePacket with unknown packet");
        return Status::InvalidArgument;
    }

    stats_.verdicts[static_cast<size_t>(verdict)]++;

    const uint64_t frameAddr = wrapper->frameAddr();
    const uint32_t caplen = wrapper->caplen();
    XdpInstance* inst = wrapper->instance();

    const bool pass = (verdict == Verdict::Pass || verdict == Verdict::Replace || verdict == Verdict::Ignore);

    if (pass && inst->peer)
    {
        if (swapMac_)
            swapMacInPlace(frameAddr, caplen);

        if (!transmitFrame(inst->peer, frameAddr, caplen))
            releaseFrame(frameAddr); // failed to hand off — recycle
    }
    else
    {
        releaseFrame(frameAddr);
    }

    wrapper->reset();
    pool_->release(wrapper);
    return Status::Success;
}

Status XdpDriver::inject(const uint8_t* data, uint32_t dataLen)
{
    if (instances_.empty())
        return Status::InvalidArgument;
    if (!data || dataLen == 0)
        return Status::InvalidArgument;
    if (dataLen > frameSize_ - headroom_)
    {
        logError("XdpDriver: inject packet too large (%u > %u)", dataLen, frameSize_ - headroom_);
        return Status::InvalidArgument;
    }

    uint64_t frameAddr = acquireFrame();
    if (frameAddr == UINT64_MAX)
    {
        for (auto* inst : instances_)
            processCq(*inst, compSize_);

        frameAddr = acquireFrame();
        if (frameAddr == UINT64_MAX)
            return Status::NoMemory;
    }

    uint8_t* dst = static_cast<uint8_t*>(umemArea_) + frameAddr + headroom_;
    std::memcpy(dst, data, dataLen);

    XdpInstance* egress = instances_.front();
    if (!transmitFrame(egress, frameAddr, dataLen))
    {
        releaseFrame(frameAddr);
        return Status::Error;
    }

    stats_.packetsInjected++;
    return Status::Success;
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
    const auto capacity = pool_ ? pool_->capacity() : 0U;
    const auto available = pool_ ? pool_->available() : 0U;

    info.capacity = capacity;
    info.available = available;
    info.memorySize = sizeof(XdpWrapper) * capacity + umemAreaSize_;
    return Status::Success;
}

} // namespace snet::driver

SNET_DLL_ALIAS(snet::driver::XdpDriver::create, CreateDriver)