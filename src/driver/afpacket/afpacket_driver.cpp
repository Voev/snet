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
#include <sys/mman.h>
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
#include <pthread.h>

using namespace casket::opt;
using namespace snet::io;

namespace snet::driver
{

bool AFPacketDriver::applyFilter()
{
    if (filter_.empty())
    {
        return true;
    }

    struct bpf_program fcode;

    pcap_t* pcap = pcap_open_dead(DLT_EN10MB, snaplen_);
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

AFPacketDriver::AFPacketDriver(const io::DriverSpec& config)
    : DriverBase(config)
{
}

AFPacketDriver::~AFPacketDriver() noexcept
{
}

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
    snaplen_ = config.getSnaplen();
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

    for (const auto& name : devices_)
    {
        auto inst = std::make_unique<Instance>(*this);
        if (!inst->create(name))
            return Status::NoSuchDevice;
        instances_.push_back(std::move(inst));
    }

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

    uint32_t numRings = 0;
    for (auto& i : instances_)
        numRings += (i->peer && useTxRing_) ? 2 : 1;

    const uint32_t totalBytes = bufferSizeMb_ * 1024 * 1024;
    const uint32_t ringSize = totalBytes / numRings;

    for (auto& inst : instances_)
    {
        inst->setRingSizeHint(ringSize);
        if (!calculateFrameSize(*inst))
            return Status::Error;
    }

    for (auto& inst : instances_)
    {
        // --- RX ring ---
        bool rxCreated = false;
        for (int order = kDefaultOrder; order >= 0; --order)
        {
            tpacket_req layout{};
            if (!calculateLayout(*inst, layout, order))
                return Status::Error;

            if (::setsockopt(inst->fd(), SOL_PACKET, PACKET_RX_RING, &layout, sizeof(layout)) == 0)
            {
                inst->rxRing.layout = layout;
                inst->rxRing.size = layout.tp_block_size * layout.tp_block_nr;
                rxCreated = true;
                break;
            }
            if (errno == ENOMEM)
            {
                logInfo("RX ring allocation on %s failed with order %d, retrying...", inst->name().c_str(), order);
                continue;
            }
            logError("couldn't create RX ring on %s: %s", inst->name().c_str(), std::strerror(errno));
            return Status::Error;
        }
        if (!rxCreated)
        {
            logError("couldn't allocate enough memory for RX ring on %s", inst->name().c_str());
            return Status::NoMemory;
        }

        // --- TX ring ---
        if (inst->peer && useTxRing_)
        {
            bool txCreated = false;
            for (int order = kDefaultOrder; order >= 0; --order)
            {
                tpacket_req layout{};
                if (!calculateLayout(*inst, layout, order))
                    return Status::Error;

                if (::setsockopt(inst->fd(), SOL_PACKET, PACKET_TX_RING, &layout, sizeof(layout)) == 0)
                {
                    inst->txRing.layout = layout;
                    inst->txRing.size = layout.tp_block_size * layout.tp_block_nr;
                    txCreated = true;
                    break;
                }
                if (errno == ENOMEM)
                    continue;
                logError("couldn't create TX ring on %s: %s", inst->name().c_str(), std::strerror(errno));
                return Status::Error;
            }
            if (!txCreated)
            {
                logError("couldn't allocate enough memory for TX ring on %s", inst->name().c_str());
                return Status::NoMemory;
            }
        }

        if (!mmapRings(*inst))
            return Status::Error;
        if (!setupRing(inst->rxRing))
            return Status::Error;
        if (inst->txRing.size && !setupRing(inst->txRing))
            return Status::Error;
    }

    uint32_t poolSize = config.getMsgPoolSize();
    if (poolSize == 0)
    {
        for (auto& i : instances_)
            poolSize += i->rxRing.layout.tp_frame_nr;
        poolSize /= 10;
        if (poolSize == 0)
            poolSize = 1;
    }

    pool_ = std::make_unique<AFPacketPool>(poolSize);
    currInstanceIdx_ = 0;

    applyFilter();

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
        if (!startInstance(*inst))
            return Status::Error;

    resetStats();
    return Status::Success;
}

bool AFPacketDriver::startInstance(Instance& inst)
{
    struct sockaddr_ll sll{};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = static_cast<int>(inst.index());
    sll.sll_protocol = htons(ETH_P_ALL);

    if (::bind(inst.fd(), reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) == -1)
    {
        logError("bind(%s) to ETH_P_ALL failed: %s", inst.name().c_str(), std::strerror(errno));
        return false;
    }

    if (fanoutEnabled_ && !configureFanout(inst))
        return false;

    inst.setActive(true);
    return true;
}

bool AFPacketDriver::configureFanout(Instance& inst)
{
    afpacket::Fanout fanout(fanoutType_, fanoutFlags_, static_cast<uint16_t>(inst.index()));
    const uint32_t arg = fanout.value();

    if (::setsockopt(inst.fd(), SOL_PACKET, PACKET_FANOUT, &arg, sizeof(arg)) == -1)
    {
        logError("could not configure packet fanout on %s: %s", inst.name().c_str(), std::strerror(errno));
        return false;
    }
    return true;
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

Status AFPacketDriver::inject(const uint8_t* data, uint32_t dataLen)
{
    if (instances_.empty())
    {
        logError("no instances to inject from");
        return Status::InvalidArgument;
    }

    if (!data || dataLen < 20)
        return Status::InvalidArgument;

    const uint8_t version = data[0] >> 4;
    if (version != 4)
    {
        logError("inject: unsupported L3 version %u", version);
        return Status::InvalidArgument;
    }

    /// @todo: use IPv4Address. And IPv6?
    uint32_t dstIp = 0;
    std::memcpy(&dstIp, data + 16, sizeof(dstIp));

    Instance* egress = findEgress(dstIp);
    if (!egress)
    {
        logError("inject: no egress for dst IP");
        return Status::Error;
    }

    if (!transmitWithEthernet(egress, data, dataLen))
        return Status::Error;

    stats_.packetsInjected++;
    return Status::Success;
}

bool AFPacketDriver::transmitPacket(Instance* egress, const uint8_t* data, uint32_t len)
{
    if (!egress)
        return true;

    if (egress->txRing.size)
    {
        auto* entry = egress->txRing.cursor;
        if (!entry)
            return false;

        auto* hdr = reinterpret_cast<tpacket2_hdr*>(entry->raw);
        if (hdr->tp_status != TP_STATUS_AVAILABLE)
        {
            logError("TX ring on %s is full", egress->name().c_str());
            return false;
        }

        std::memcpy(entry->raw + SNET_TPACKET_ALIGN(egress->hdrLen()), data, len);
        hdr->tp_len = len;
        hdr->tp_status = TP_STATUS_SEND_REQUEST;

        if (::send(egress->fd(), nullptr, 0, 0) < 0)
        {
            logError("send() via TX ring on %s: %s", egress->name().c_str(), std::strerror(errno));
            return false;
        }
        egress->txRing.cursor = entry->next;
    }
    else
    {
        while (::send(egress->fd(), data, len, 0) < 0)
        {
            if (errno == ENOBUFS)
            {
                struct pollfd pfd{};
                pfd.fd = egress->fd();
                pfd.events = POLLOUT;
                if (::poll(&pfd, 1, 10) > 0 && (pfd.revents & POLLOUT))
                    continue;
            }
            logError("error sending data over socket %s: %s", egress->name().c_str(), std::strerror(errno));
            return false;
        }
    }
    return true;
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

int AFPacketDriver::getSnaplen() const
{
    return instances_.empty() ? 0 : static_cast<int>(instances_.front()->snaplen());
}

snet::layers::LinkLayerType AFPacketDriver::getDataLinkType() const
{
    return snet::layers::LinkLayerType::LINKTYPE_ETHERNET;
}

RecvStatus AFPacketDriver::receivePackets(snet::layers::Packet** rawPacket, uint16_t* packetCount, uint16_t maxCount)
{
    if (!rawPacket || !packetCount || maxCount == 0)
    {
        if (packetCount)
            *packetCount = 0;
        return RecvStatus::Ok;
    }

    if (!pool_)
    {
        logError("receivePackets called before configure()");
        *packetCount = 0;
        return RecvStatus::Error;
    }

    uint16_t idx = 0;
    RecvStatus status = RecvStatus::Ok;

    while (idx < maxCount)
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

        RingEntry* entry = findPacket();
        if (!entry)
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

        Instance* instance = instances_[currInstanceIdx_].get();
        auto* hdr = reinterpret_cast<tpacket2_hdr*>(entry->raw);

        const uint32_t tpLen = hdr->tp_len;
        const uint32_t tpMac = hdr->tp_mac;
        uint32_t tpSnaplen = hdr->tp_snaplen;

        if (tpMac + tpSnaplen > instance->rxRing.layout.tp_frame_size)
        {
            logError("corrupted frame on %s (MAC %u + CapLen %u > FrameSize %u)",
                     instance->name().c_str(),
                     tpMac,
                     tpSnaplen,
                     instance->rxRing.layout.tp_frame_size);
            hdr->tp_status = TP_STATUS_KERNEL;
            pool_->release(wrapper);
            status = RecvStatus::Error;
            break;
        }

        uint8_t* data = entry->raw + tpMac;

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

        if (fcode_.bf_insns && bpf_filter(fcode_.bf_insns, data, tpLen, tpSnaplen) == 0)
        {
            stats_.packetsFiltered++;
            transmitPacket(instance->peer, data, tpSnaplen);

            auto* hdr = reinterpret_cast<tpacket2_hdr*>(entry->raw);
            hdr->tp_status = TP_STATUS_KERNEL;

            pool_->release(wrapper);
            continue;
        }

        stats_.packetsReceived++;

        wrapper->attach(data, tpSnaplen, tpLen, instance, entry);
        rawPacket[idx++] = wrapper->asPacket();
    }

    *packetCount = idx;
    return status;
}

Status AFPacketDriver::finalizePacket(snet::layers::Packet* rawPacket, Verdict verdict)
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

    const bool pass = (verdict == Verdict::Pass || verdict == Verdict::Replace || verdict == Verdict::Ignore);

    if (pass && wrapper->instance()->peer)
    {
        Instance* self = wrapper->instance();
        Instance* peer = self->peer;

        uint8_t* frame = const_cast<uint8_t*>(wrapper->asPacket()->getData());
        const size_t len = wrapper->caplen();

        rewriteEthernetForBridge(self, peer, frame, len);

        if (!transmitPacket(peer, frame, len))
        {
            logError("failed to forward packet out of %s", peer->name().c_str());
        }
    }

    auto* hdr = reinterpret_cast<tpacket2_hdr*>(wrapper->entry()->raw);
    hdr->tp_status = TP_STATUS_KERNEL;

    pool_->release(wrapper);
    return Status::Success;
}

Status AFPacketDriver::injectPacket(layers::Packet* rawPacket)
{
    if (!rawPacket)
    {
        return Status::InvalidArgument;
    }

    auto* memPkt = layers::InMemoryPacket::fromPacket(rawPacket);
    if (!memPkt)
    {
        logError("inject: packet isn't an in-memory type");
        return Status::Error;
    }

    const size_t headroom = memPkt->headroom();
    if (headroom < ETH_HLEN)
    {
        logError("inject: headroom %zu < ETH_HLEN %d", headroom, ETH_HLEN);
        return Status::InvalidArgument;
    }

    const uint8_t* ipData = rawPacket->getData();
    const uint32_t ipLen = static_cast<uint32_t>(rawPacket->getDataLen());

    if (ipLen < 20 || (ipData[0] >> 4) != 4)
    {
        logError("inject: not IPv4");
        return Status::InvalidArgument;
    }

    /// @todo: use IPv4Address. And IPv6?
    uint32_t dstIp = 0;
    std::memcpy(&dstIp, ipData + 16, sizeof(dstIp));

    Instance* egress = findEgress(dstIp);
    if (!egress)
    {
        logError("inject: no egress for dst IP");
        return Status::Error;
    }

    layers::MacAddress dstMac;
    if (!lookupNeighborMac(dstIp, dstMac))
    {
        logError("inject: no ARP entry for dst IP");
        return Status::Error;
    }

    const layers::MacAddress srcMac = egress->mac();
    uint8_t* eth = memPkt->getBufferStart();

    layers::HeaderBuilder<layers::ethernet_header> builder(eth,
                                                           headroom,
                                                           [](size_t) noexcept
                                                           {
                                                           });

    builder.set(&layers::ethernet_header::dstMac, dstMac.bytes)
        .set(&layers::ethernet_header::srcMac, srcMac.bytes)
        .set(&layers::ethernet_header::etherType, casket::host_to_be(static_cast<uint16_t>(layers::EtherType::IP)))
        .build();

    const uint32_t frameLen = ETH_HLEN + ipLen;

    if (!transmitPacket(egress, eth, frameLen))
        return Status::Error;

    stats_.packetsInjected++;
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

bool AFPacketDriver::calculateFrameSize(Instance& inst)
{
    const unsigned tpHdrlenSll = SNET_TPACKET_ALIGN(inst.hdrLen()) + sizeof(sockaddr_ll);
    const unsigned netoff = SNET_TPACKET_ALIGN(tpHdrlenSll + (ETH_HLEN < 16 ? 16 : ETH_HLEN)) + inst.tpReserve;
    const unsigned macoff = netoff - ETH_HLEN;

    const unsigned frameSize = SNET_TPACKET_ALIGN(macoff + static_cast<unsigned>(snaplen_));

    inst.setFrameSize(frameSize);
    inst.setActualSnaplen(frameSize - macoff);
    return true;
}

bool AFPacketDriver::calculateLayout(Instance& inst, tpacket_req& layout, int order)
{
    layout.tp_frame_size = inst.frameSize();
    layout.tp_block_size = static_cast<unsigned>(::getpagesize()) << order;
    while (layout.tp_block_size < layout.tp_frame_size)
        layout.tp_block_size <<= 1;

    const unsigned framesPerBlock = layout.tp_block_size / layout.tp_frame_size;
    if (framesPerBlock == 0)
    {
        logError(
            "invalid frames per block (%u/%u) for %s", layout.tp_block_size, layout.tp_frame_size, inst.name().c_str());
        return false;
    }

    layout.tp_frame_nr = inst.ringSizeHint() / layout.tp_frame_size;
    layout.tp_block_nr = layout.tp_frame_nr / framesPerBlock;
    layout.tp_frame_nr = layout.tp_block_nr * framesPerBlock;

    logInfo("afpacket[%s] layout: frame=%u frames=%u block=%u blocks=%u",
            inst.name().c_str(),
            layout.tp_frame_size,
            layout.tp_frame_nr,
            layout.tp_block_size,
            layout.tp_block_nr);
    return true;
}

bool AFPacketDriver::mmapRings(Instance& inst)
{
    const unsigned ringSize = inst.rxRing.size + inst.txRing.size;
    void* buf = ::mmap(nullptr, ringSize, PROT_READ | PROT_WRITE, MAP_SHARED, inst.fd(), 0);
    if (buf == MAP_FAILED)
    {
        logError("could not MMAP the ring on %s: %s", inst.name().c_str(), std::strerror(errno));
        return false;
    }

    inst.setBuffer(buf);
    inst.rxRing.start = buf;
    if (inst.txRing.size)
        inst.txRing.start = static_cast<uint8_t*>(buf) + inst.rxRing.size;
    return true;
}

bool AFPacketDriver::setupRing(Ring& ring)
{
    ring.entries = static_cast<RingEntry*>(::calloc(ring.layout.tp_frame_nr, sizeof(RingEntry)));
    if (!ring.entries)
    {
        logError("could not allocate ring entries");
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

void AFPacketDriver::updateHwStats()
{
    struct tpacket_stats kstats{};
    socklen_t len = sizeof(kstats);
    for (auto& inst : instances_)
    {
        if (!inst->active() || inst->fd() == -1)
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

RingEntry* AFPacketDriver::findPacket()
{
    if (instances_.empty())
        return nullptr;

    const size_t n = instances_.size();
    for (size_t i = 0; i < n; ++i)
    {
        const size_t idx = (currInstanceIdx_ + 1 + i) % n;
        auto& inst = instances_[idx];

        auto* hdr = reinterpret_cast<tpacket2_hdr*>(inst->rxRing.cursor->raw);
        if (hdr->tp_status & TP_STATUS_USER)
        {
            currInstanceIdx_ = idx;
            auto* entry = inst->rxRing.cursor;
            inst->rxRing.cursor = entry->next;
            return entry;
        }
    }
    return nullptr;
}

RecvStatus AFPacketDriver::waitForPacket()
{
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
    {
        if (!inst->rxRing.entries)
            continue;
        for (uint32_t i = 0; i < inst->rxRing.layout.tp_frame_nr; ++i)
        {
            auto* hdr = reinterpret_cast<tpacket2_hdr*>(inst->rxRing.entries[i].raw);
            if (hdr->tp_status & TP_STATUS_USER)
                hdr->tp_status = TP_STATUS_KERNEL;
        }
    }
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