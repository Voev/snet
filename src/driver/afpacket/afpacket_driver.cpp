#include "afpacket_driver.hpp"
#include "afpacket_fanout.hpp"

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
#include <sys/socket.h>
#include <unistd.h>

#include <casket/log/log.hpp>
#include <casket/opt/opt.hpp>

#include <snet/layers/header_builder.hpp>
#include <snet/layers/in_memory_packet.hpp>

#ifndef POLLRDHUP
#define POLLRDHUP 0x2000
#endif

#include <pcap.h>

using namespace casket::opt;
using namespace snet::io;

namespace snet::driver
{

AFPacketDriver::AFPacketDriver(const io::DriverSpec& config)
    : DriverBase(config)
{
}

AFPacketDriver::~AFPacketDriver() noexcept = default;

std::shared_ptr<io::Driver> AFPacketDriver::create(const io::DriverSpec& config)
{
    return std::make_shared<AFPacketDriver>(config);
}

const char* AFPacketDriver::getName() const
{
    return "af_packet";
}

Status AFPacketDriver::declareOptions(io::Config& config)
{
    // clang-format off
    config.addDriverOption(OptionBuilder("buffer_size_mb", Value(&bufferSizeMb_))
        .setDefaultValue(kDefaultBufferMb)
        .setDescription("Packet buffer space to allocate in megabytes")
        .build());
    config.addDriverOption(OptionBuilder("use_tx_ring", Value(&useTxRing_))
        .setDefaultValue(false)
        .setDescription("Use memory-mapped TX ring")
        .build());
    config.addDriverOption(OptionBuilder("fanout_enabled", Value(&fanoutEnabled_))
        .setDefaultValue(false)
        .setDescription("Enable AF_PACKET fanout")
        .build());
    config.addDriverOption(OptionBuilder("fanout_type", Value(&fanoutType_))
        .setDefaultValue(afpacket::Fanout::Type::Hash)
        .setDescription("Fanout type: hash|lb|cpu|rollover|rnd|qm")
        .build());
    config.addDriverOption(OptionBuilder("fanout_flags", Value(&fanoutFlags_))
        .setDefaultValue(afpacket::Fanout::Flags::None)
        .setDescription("Fanout flags: none|rollover|uniqueid|defrag")
        .build());
    config.addDriverOption(OptionBuilder("bpf_filter", Value(&filter_))
        .setDescription("BPF filter string")
        .build());
    // clang-format on
    return Status::Success;
}

Status AFPacketDriver::configure(const snet::io::Config& config)
{
    snaplen_ = static_cast<size_t>(config.getSnaplen());
    timeoutMs_ = config.getTimeout();
    if (timeoutMs_ == 0)
        timeoutMs_ = -1;

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
    if (devices_.size() > kMaxInterfaces)
    {
        logError("using more than %zu interfaces is not supported", kMaxInterfaces);
        return Status::InvalidArgument;
    }

    io::DeviceId id{0};
    for (const auto& name : devices_)
    {
        auto inst = std::make_unique<Instance>(*this, id++);
        if (!inst->create(name))
            return Status::NoSuchDevice;
        instances_.push_back(std::move(inst));
    }

    const uint32_t totalBytes = bufferSizeMb_ * 1024 * 1024;
    const uint32_t perDevice = totalBytes / static_cast<uint32_t>(instances_.size());

    for (auto& inst : instances_)
    {
        Instance::RingConfig cfg{perDevice, static_cast<uint32_t>(snaplen_), useTxRing_};
        if (!inst->createRings(cfg))
            return Status::Error;
    }

    uint32_t poolSize = config.getMsgPoolSize();
    if (poolSize == 0)
    {
        for (auto& i : instances_)
            poolSize += i->rxFrameCount();
        poolSize /= 10;
        if (poolSize == 0)
            poolSize = 1;
    }

    pool_ = std::make_unique<AFPacketPool>(poolSize);
    currInstanceIdx_ = 0;

    if (!applyFilter())
        return Status::Error;

    return Status::Success;
}

Status AFPacketDriver::start()
{
    if (instances_.empty())
    {
        logError("start() called before configure()");
        return Status::InvalidArgument;
    }

    for (auto& inst : instances_)
    {
        if (!inst->bindTo(ETH_P_ALL))
            return Status::Error;

        if (fanoutEnabled_ && !inst->configureFanout(fanoutType_, fanoutFlags_))
            return Status::Error;
    }

    resetStats();
    return Status::Success;
}

Status AFPacketDriver::stop()
{
    updateHwStats();
    releaseAllOutstandingFrames();
    pool_.reset();
    instances_.clear();
    currInstanceIdx_ = 0;
    return Status::Success;
}

Status AFPacketDriver::interrupt()
{
    interrupted_.store(true, std::memory_order_release);
    return Status::Success;
}

size_t AFPacketDriver::deviceCount() const
{
    return instances_.size();
}

io::Device* AFPacketDriver::deviceAt(size_t idx) const
{
    return idx < instances_.size() ? instances_[idx].get() : nullptr;
}

bool AFPacketDriver::findFrame(Instance*& outInst, Instance::RxFrame& outFrame)
{
    outInst = nullptr;
    if (instances_.empty())
        return false;

    const size_t n = instances_.size();
    for (size_t i = 0; i < n; ++i)
    {
        const size_t idx = (currInstanceIdx_ + 1 + i) % n;
        auto* inst = instances_[idx].get();

        if (inst->receive(outFrame) == Instance::RxStatus::Ok)
        {
            currInstanceIdx_ = idx;
            outInst = inst;
            return true;
        }
    }
    return false;
}

RecvStatus AFPacketDriver::receivePackets(io::Driver::RxItem* out, uint16_t* count, uint16_t max)
{
    if (!out || max == 0)
    {
        return RecvStatus::Eof;
    }

    if (!pool_)
    {
        logError("receivePackets called before configure()");
        return RecvStatus::Error;
    }

    uint16_t idx = 0;
    RecvStatus status = RecvStatus::Ok;

    while (idx < max)
    {
        if (interrupted_.load(std::memory_order_acquire))
        {
            interrupted_.store(false, std::memory_order_release);
            status = RecvStatus::Interrupted;
            break;
        }

        AFPacketWrapper* wrapper = pool_->acquire();
        if (!wrapper)
        {
            logError("no free AFPacketWrapper (pool is exhausted)");
            status = RecvStatus::NoBuffer;
            break;
        }

        Instance* instance = nullptr;
        Instance::RxFrame frame{};
        if (!findFrame(instance, frame))
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

        stats_.packetsReceived++;
        wrapper->attach(frame.data, frame.caplen, frame.len, instance, frame.entry);
        out[idx].packet = wrapper->asPacket();
        out[idx].ingress = instance->id();
        idx++;
    }

    if (count)
    {
        *count = idx;
    }
    return status;
}

Status AFPacketDriver::finalizePacket(layers::Packet* rawPacket, Verdict verdict)
{
    if (!rawPacket)
    {
        logError("finalizePacket called with null packet");
        return Status::InvalidArgument;
    }

    AFPacketWrapper* wrapper = AFPacketWrapper::fromPacket(rawPacket);
    if (!wrapper || !wrapper->entry() || !wrapper->instance())
    {
        logError("finalizePacket called with unknown packet");
        return Status::InvalidArgument;
    }

    stats_.verdicts[static_cast<size_t>(verdict)]++;

    wrapper->instance()->releaseFrame(wrapper->entry());
    pool_->release(wrapper);
    return Status::Success;
}

Status AFPacketDriver::transmitPacket(layers::Packet* packet, io::DeviceId egress)
{
    if (instances_.empty())
    {
        logError("transmitPacket: no instances");
        return Status::InvalidArgument;
    }

    Instance* instance{nullptr};

    for (size_t i = 0; i < instances_.size(); ++i)
    {
        if (instances_[i]->id() == egress)
        {
            instance = instances_[i].get();
            break;
        }
    }

    if (!instance)
    {
        logError("transmitPacket: device not found");
        return Status::NoSuchDevice;
    }

    if (!instance->send(packet->getData(), packet->getDataLen()))
    {
        logError("transmitPacket: failed to transmit");
        return Status::Error;
    }

    stats_.packetsTransmitted++;
    return Status::Success;
}

Status AFPacketDriver::getMsgPoolInfo(snet::io::PacketPoolInfo& info)
{
    auto capacity = pool_ ? pool_->capacity() : 0U;
    auto available = pool_ ? pool_->available() : 0U;

    info.capacity = capacity;
    info.available = available;
    info.memorySize = sizeof(AFPacketWrapper) * capacity;
    return Status::Success;
}

Status AFPacketDriver::getStats(Stats* stats)
{
    updateHwStats();
    if (stats)
        *stats = stats_;
    return Status::Success;
}

void AFPacketDriver::resetStats()
{
    stats_ = Stats{};

    struct tpacket_stats kstats{};
    socklen_t len = sizeof(kstats);
    for (auto& inst : instances_)
    {
        if (inst->fd() != -1)
            ::getsockopt(inst->fd(), SOL_PACKET, PACKET_STATISTICS, &kstats, &len);
    }
}

snet::layers::LinkLayerType AFPacketDriver::getDataLinkType() const
{
    return snet::layers::LinkLayerType::LINKTYPE_ETHERNET;
}

void AFPacketDriver::updateHwStats()
{
    struct tpacket_stats kstats{};
    socklen_t len = sizeof(kstats);
    for (auto& inst : instances_)
    {
        if (inst->fd() == -1)
            continue;

        std::memset(&kstats, 0, len);
        if (::getsockopt(inst->fd(), SOL_PACKET, PACKET_STATISTICS, &kstats, &len) > -1)
        {
            stats_.hwPacketsReceived += kstats.tp_packets - kstats.tp_drops;
            stats_.hwPacketsDropped += kstats.tp_drops;
        }
        else
        {
            logError("failed to get stats for %s: %s", inst->name().c_str(), std::strerror(errno));
        }
    }
}

RecvStatus AFPacketDriver::waitForPacket()
{
    if (instances_.empty())
        return RecvStatus::Error;

    std::vector<pollfd> pfds(instances_.size());
    for (size_t i = 0; i < instances_.size(); ++i)
    {
        pfds[i].fd = instances_[i]->fd();
        pfds[i].events = POLLIN;
        pfds[i].revents = 0;
    }

    int timeout = timeoutMs_;
    while (timeout != 0)
    {
        if (interrupted_.load(std::memory_order_acquire))
        {
            interrupted_.store(false, std::memory_order_release);
            return RecvStatus::Interrupted;
        }

        int pollTimeout;
        if (timeout >= 1000)
        {
            pollTimeout = 1000;
            timeout -= 1000;
        }
        else if (timeout > 0)
        {
            pollTimeout = timeout;
            timeout = 0;
        }
        else
        {
            pollTimeout = 1000;
        }

        const int ret = ::poll(pfds.data(), pfds.size(), pollTimeout);
        if (ret > 0)
        {
            for (auto& p : pfds)
            {
                if (p.revents & (POLLHUP | POLLRDHUP | POLLERR | POLLNVAL))
                {
                    if (p.revents & (POLLHUP | POLLRDHUP))
                        logError("hang-up on a packet socket");
                    else if (p.revents & POLLERR)
                        logError("error condition on a packet socket");
                    else
                        logError("invalid polling request on a packet socket");
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
    return RecvStatus::Timeout;
}

void AFPacketDriver::releaseAllOutstandingFrames()
{
    for (auto& inst : instances_)
        inst->releaseOutstandingFrames();
}

bool AFPacketDriver::applyFilter()
{
    if (filter_.empty())
        return true;

    struct bpf_program fcode;
    pcap_t* pcap = pcap_open_dead(DLT_EN10MB, static_cast<int>(snaplen_));
    if (pcap == nullptr)
    {
        logError("AFPacketDriver: pcap_open_dead failed");
        return false;
    }

    if (pcap_compile(pcap, &fcode, filter_.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1)
    {
        logError("AFPacketDriver: pcap_compile failed: %s", pcap_geterr(pcap));
        pcap_close(pcap);
        return false;
    }
    pcap_close(pcap);

    pcap_freecode(&fcode_);
    fcode_ = fcode;
    return true;
}

void AFPacketDriver::rewriteEthernetForBridge(Instance* self, Instance* peer, uint8_t* frame, size_t len) const noexcept
{
    if (!self || !peer || !frame || len < ETH_HLEN)
        return;

    uint32_t dstIp = 0;
    std::memcpy(&dstIp, frame + ETH_HLEN + 16, sizeof(dstIp));

    layers::MacAddress dstMac{};
    if (!lookupNeighborMac(dstIp, dstMac))
    {
        logError("bridge: no ARP for dst IP on %s", peer->name().c_str());
        return;
    }

    std::memcpy(frame, dstMac.data(), ETH_ALEN);
    std::memcpy(frame + ETH_ALEN, peer->mac().data(), ETH_ALEN);
}

/// @todo: use IPv4Address. And IPv6?
Instance* AFPacketDriver::findEgress(uint32_t dstIp) const noexcept
{
    for (const auto& inst : instances_)
    {
        if (inst->netmask() == 0)
            continue;
        if ((dstIp & inst->netmask()) == (inst->ip() & inst->netmask()))
            return inst.get();
    }
    return nullptr;
}

/// @todo: use IPv4Address. And IPv6?
bool AFPacketDriver::lookupNeighborMac(uint32_t dstIp, layers::MacAddress& mac) const
{
    std::FILE* f = std::fopen("/proc/net/arp", "r");
    if (!f)
        return false;

    char line[256];
    if (!std::fgets(line, sizeof(line), f))
    {
        std::fclose(f);
        return false;
    }

    while (std::fgets(line, sizeof(line), f))
    {
        char ipStr[64]{};
        char hwStr[64]{};
        char maskStr[64]{};
        char devStr[64]{};
        unsigned hwType = 0;
        unsigned flags = 0;

        // Format of /proc/net/arp:
        //   IP address  HW type  Flags  HW address       Mask  Device
        //   10.0.1.1    0x1      0x2    fa:11:e2:5b:66:c2 *     veth-ps
        const int n =
            std::sscanf(line, "%63s 0x%x 0x%x %63s %63s %63s", ipStr, &hwType, &flags, hwStr, maskStr, devStr);
        if (n != 6)
            continue;

        struct in_addr addr{};
        if (::inet_aton(ipStr, &addr) == 0)
            continue;
        if (addr.s_addr != dstIp)
            continue;

        unsigned m[6]{};
        if (std::sscanf(hwStr, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
            continue;

        for (size_t i = 0; i < mac.bytes.size(); ++i)
            mac.bytes[i] = static_cast<uint8_t>(m[i]);

        std::fclose(f);
        return true;
    }

    std::fclose(f);
    return false;
}

} // namespace snet::driver

SNET_DLL_ALIAS(snet::driver::AFPacketDriver::create, CreateDriver)