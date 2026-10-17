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

inline std::string trimCopy(nonstd::string_view s)
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

        std::string tok = trimCopy(nonstd::string_view{input}.substr(pos, comma - pos));
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
                ep.iface = trimCopy(nonstd::string_view{tok}.substr(0, colon));
                const std::string qstr = trimCopy(nonstd::string_view{tok}.substr(colon + 1));
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

Status XdpDriver::configure(const snet::io::Config& config)
{
    auto snaplen = config.getSnaplen();
    timeoutMs_ = config.getTimeout();
    if (timeoutMs_ == 0)
    {
        timeoutMs_ = -1;
    }

    if (auto st = parseEndpoints(config.getInput()); st != Status::Success)
        return st;

    if (frameSize_ < headroom_ + snaplen)
    {
        logError("XdpDriver: frame_size (%u) < frame_headroom + snaplen (%zu)", frameSize_, headroom_ + snaplen);
        return Status::InvalidArgument;
    }
    if (numFrames_ < fillSize_ + rxSize_)
    {
        logError("XdpDriver: num_frames (%u) must be >= fill_size + rx_size (%u)", numFrames_, fillSize_ + rxSize_);
        return Status::InvalidArgument;
    }

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

    for (const auto& ep : endpoints_)
    {
        const io::DeviceId devId = static_cast<io::DeviceId>(instancesOwned_.size());

        auto inst = std::make_unique<XdpInstance>(*this, devId);
        if (!inst->configure(ep.iface, ep.queue))
        {
            return Status::NoSuchDevice;
        }

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

    uint32_t poolSize = config.getMsgPoolSize();
    if (poolSize == 0)
        poolSize = std::min<uint32_t>(numFrames_, xdp::kDefaultMsgPoolSize);

    pool_ = std::make_unique<XdpPool>(poolSize);

    logInfo(
        "XdpDriver: configured %zu iface(s), %zu endpoint(s), pool=%u", ifaces_.size(), instances_.size(), poolSize);
    return Status::Success;
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

    // One shared UMEM, one AF_XDP socket per endpoint.
    // libbpf_flags = 0 → libxdp loads its built-in xsk_def_prog and
    // registers the socket in the XSKMAP automatically.
    struct xsk_socket_config cfg{};
    cfg.rx_size = rxSize_;
    cfg.tx_size = txSize_;
    cfg.libbpf_flags = 0;
    cfg.xdp_flags = zeroCopy_ ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
    cfg.bind_flags = needWakeup_ ? XDP_USE_NEED_WAKEUP : 0;

    for (auto* inst : instances_)
    {
        if (!inst->create(umem_, cfg))
        {
            stop();
            return Status::Error;
        }
    }

    // Prime FQ for every endpoint.
    for (auto* inst : instances_)
        inst->refillFq(fillSize_);

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

    destroyUmem();
    clearAll();

    const uint32_t leaked = numFrames_ - freeFrameCount();
    if (leaked > 0)
    {
        logWarning("XdpDriver: stopping with %u frame(s) still in flight", leaked);
    }

    return Status::Success;
}

void XdpDriver::clearAll()
{
    instances_.clear();
    instancesOwned_.clear();
    ifaces_.clear();
    pool_.reset();
    freeFrames_.clear();
    currInstanceIdx_ = 0;
}

Status XdpDriver::interrupt()
{
    interrupted_.store(true, std::memory_order_release);
    return Status::Success;
}

size_t XdpDriver::deviceCount() const
{
    return instances_.size();
}

io::Device* XdpDriver::deviceAt(size_t idx) const
{
    if (idx >= instances_.size())
        return nullptr;
    return static_cast<io::Device*>(instances_[idx]);
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

    freeFrames_.clear();
    freeFrames_.reserve(numFrames_);
    for (uint32_t i = 0; i < numFrames_; ++i)
    {
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

uint64_t XdpDriver::acquireFrame()
{
    if (freeFrames_.empty())
    {
        return UINT64_MAX;
    }
    uint64_t a = freeFrames_.back();
    freeFrames_.pop_back();
    return a;
}

void XdpDriver::releaseFrame(uint64_t addr)
{
    freeFrames_.push_back(addr);
}

uint32_t XdpDriver::freeFrameCount() const noexcept
{
    return static_cast<uint32_t>(freeFrames_.size());
}

RecvStatus XdpDriver::receivePackets(RxItem* rx, uint16_t* count, uint16_t max)
{
    if (!rx || max == 0)
        return RecvStatus::Eof;

    if (!pool_ || instances_.empty())
    {
        logError("XdpDriver: receivePackets called before start()");
        return RecvStatus::Error;
    }

    if (interrupted_.load(std::memory_order_acquire))
    {
        interrupted_.store(false, std::memory_order_release);
        return RecvStatus::Interrupted;
    }

    // Reclaim completions + refill FQ for every endpoint.
    for (auto* inst : instances_)
    {
        inst->processCq(compSize_);
        inst->refillFq(fillSize_ / 2);
    }

    uint16_t idx = 0;
    RecvStatus status = RecvStatus::Ok;
    const uint16_t budget = std::min<uint16_t>(max, static_cast<uint16_t>(batchSize_));

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
                for (uint32_t j = k; j < n; ++j)
                {
                    const struct xdp_desc* dj = ::xsk_ring_cons__rx_desc(inst->rxRing(), pos + j);
                    releaseFrame(dj->addr);
                }
                ::xsk_ring_cons__release(inst->rxRing(), n);
                if (idx == 0)
                {
                    status = RecvStatus::NoBuffer;
                }
                goto done;
            }

            uint8_t* data = static_cast<uint8_t*>(umemArea_) + d->addr + headroom_;
            const uint32_t cap = d->len;

            wrapper->attach(data, cap, cap, inst, d->addr);
            rx[idx].packet = wrapper->asPacket();
            rx[idx].ingress = inst->id();
            idx++;
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
    if (count)
        *count = idx;
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

    // The verdict policy lives in the userspace caller, not here.
    // Driver only reclaims the frame and returns the wrapper to the pool.
    releaseFrame(frameAddr);
    wrapper->reset();
    pool_->release(wrapper);
    return Status::Success;
}

Status XdpDriver::transmitPacket(layers::Packet* packet, io::DeviceId egress)
{
    if (!packet)
        return Status::InvalidArgument;

    if (egress >= instances_.size())
        return Status::NoSuchDevice;

    XdpInstance* inst = instances_[egress];
    if (!inst || !inst->active())
        return Status::NoSuchDevice;

    // io::Device::send handles frame allocation, copy and TX submit.
    if (!inst->send(packet->getData(), packet->getDataLen()))
        return Status::Error;

    stats_.packetsTransmitted++;
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