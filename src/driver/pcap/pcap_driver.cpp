#include <errno.h>
#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#include <casket/utils/string.hpp>
#include <casket/utils/to_number.hpp>

#include <snet/utils/counter.hpp>

#include "pcap_driver.hpp"
#include "pcap_handle.hpp"
#include "pcap_packet.hpp"

#define PCAP_ROLLOVER_LIM 1000000000 // Check for rollover every billionth packet

static pthread_mutex_t bpf_mutex = PTHREAD_MUTEX_INITIALIZER;

using namespace casket;
using namespace snet::layers;

struct BpfProgramDeleter
{
    void operator()(bpf_program* prog) const
    {
        if (prog)
        {
            pcap_freecode(prog);
        }
    }
};

using BpfProgramPtr = std::unique_ptr<bpf_program, BpfProgramDeleter>;

namespace snet::driver
{

Pcap::Pcap(const io::DriverConfig& config)
    : handle_(nullptr)
    , fp_(nullptr)
    , snaplen_(0)
    , timeout_(0)
    , bufferSize_(0)
    , mode_(Mode::None)
    , netmask_(0)
    , hwupdateCount_(0)
    , promiscMode_(true)
    , immediateMode_(true)
    , nonblocking_(false)
    , interrupted_(false)
{
    (void)config;
}

Pcap::~Pcap() noexcept
{
    if (fp_)
    {
        fclose(fp_);
    }
}

std::shared_ptr<io::Driver> Pcap::create(const io::DriverConfig& config)
{
    return std::make_shared<Pcap>(config);
}

const char* Pcap::getName() const
{
    return "pcap";
}

Status Pcap::configure(const io::Config& config)
{
    snaplen_ = config.getSnaplen();
    timeout_ = config.getTimeout();
    mode_ = config.getMode();

    for (const auto& [name, value] : config.getParameters())
    {
        if (iequals(name, "buffer_size"))
        {
            to_number(value, bufferSize_);
        }
        else if (iequals(name, "no_promiscuous"))
        {
            promiscMode_ = false;
        }
        else if (iequals(name, "no_immediate"))
        {
            immediateMode_ = false;
        }
    }

    pool_ = std::make_unique<PacketPool<PcapPacket>>(config.getMsgPoolSize(), config.getSnaplen());

    if (mode_ == Mode::ReadFile)
    {
        const auto fname = config.getInput();
        if (fname[0] == '-' && fname[1] == '\0')
        {
            fp_ = stdin;
        }
        else
        {
            fp_ = fopen(fname.c_str(), "rb");
            if (!fp_)
            {
                return Status::InvalidArgument;
            }
        }
    }
    else if (mode_ == Mode::Passive)
    {
        device_ = config.getInput();
        if (device_.empty())
        {
            return Status::InvalidArgument;
        }
    }
    else
    {
        return Status::NotSupported;
    }

    hwupdateCount_ = 0;
    return Status::Success;
}

Status Pcap::start()
{
    if (!device_.empty())
    {
        return startLive();
    }
    else
    {
        return startOffline();
    }
}

Status Pcap::stop()
{
    if (handle_)
    {
        /// Store the hardware stats for post-stop stat calls.
        updateHwStats();
        handle_.reset();
    }
    return Status::Success;
}

Status Pcap::interrupt()
{
    interrupted_ = true;
    return Status::Success;
}

RecvStatus Pcap::receivePackets(layers::Packet** packets, uint16_t* packetCount, uint16_t maxCount)
{
    RecvStatus rstat{RecvStatus::Ok};
    struct pcap_pkthdr* pcaphdr{nullptr};
    const uint8_t* data{nullptr};
    uint16_t i{};
    PcapPacket* packet{nullptr};
    int ret{};

    for (i = 0; i < maxCount; ++i)
    {
        if (interrupted_)
        {
            interrupted_ = false;
            rstat = RecvStatus::Interrupted;
            break;
        }

        packet = pool_->acquire();
        if (!packet)
        {
            rstat = RecvStatus::NoMemory;
            break;
        }

        // When dealing with a live interface, try to get the first packet in non-blocking mode.
        // If there's nothing to receive, switch to blocking mode.

        if (mode_ != Mode::ReadFile && i == 0)
        {
            if (setNonBlocking(true) != Status::Success)
            {
                rstat = RecvStatus::Error;
            }
            else
            {
                ret = pcap_next_ex(handle_, &pcaphdr, &data);
                if (ret == 0)
                {
                    if (setNonBlocking(false) != Status::Success)
                    {
                        rstat = RecvStatus::Error;
                        break;
                    }
                    ret = pcap_next_ex(handle_, &pcaphdr, &data);
                }
            }
        }
        else
        {
            ret = pcap_next_ex(handle_, &pcaphdr, &data);
        }

        if (ret <= 0)
        {
            if (ret == 0)
            {
                rstat = RecvStatus::Timeout;
            }
            else if (ret == -1)
            {
                rstat = RecvStatus::Error;
            }
            else if (ret == -2)
            {
                if (!interrupted_ && mode_ == Mode::ReadFile)
                {
                    rstat = RecvStatus::Eof;
                }
                else
                {
                    interrupted_ = false;
                    rstat = RecvStatus::Interrupted;
                }
                break;
            }
        }

        if (++hwupdateCount_ == PCAP_ROLLOVER_LIM)
        {
            updateHwStats();
        }

        struct timeval ts{};
        ts.tv_sec = pcaphdr->ts.tv_sec;
        ts.tv_usec = pcaphdr->ts.tv_usec;

        packet->packet.setTimestamp(Timestamp(ts));

        int caplen = (pcaphdr->caplen > snaplen_) ? snaplen_ : pcaphdr->caplen;

        memcpy(packet->data, data, caplen);

        if (!packet->packet.setRawData({packet->data, (size_t)caplen}, getDataLinkType(), -1))
        {
            rstat = RecvStatus::Error;
        }
        else
        {
            stats_.packets_received++;
        }

        packets[i] = &packet->packet;
    }

    *packetCount = i;
    return rstat;
}

RecvStatus Pcap::receivePacket(layers::Packet**)
{
    return RecvStatus::Error;
}

Status Pcap::finalizePacket(layers::Packet* packet, Verdict verdict)
{
    auto innerPacket = PcapPacket::fromPacket(packet);
    stats_.verdicts[verdict]++;
    packet->clear();
    pool_->release(innerPacket);

    return Status::Success;
}

Status Pcap::inject(const uint8_t* data, uint32_t dataLength)
{
    if (0 > pcap_inject(handle_, data, dataLength))
    {
        return Status::Error;
    }

    stats_.packets_injected++;
    return Status::Success;
}

int Pcap::getSnaplen() const
{
    return snaplen_;
}

layers::LinkLayerType Pcap::getDataLinkType() const
{
    if (handle_)
    {
        return static_cast<layers::LinkLayerType>(pcap_datalink(handle_));
    }
    return layers::LINKTYPE_NULL;
}

Status Pcap::getMsgPoolInfo(PacketPoolInfo& info)
{
    pool_->getInfo(info);
    return Status::Success;
}

Status Pcap::getStats(Stats* stats)
{
    if (updateHwStats() != Status::Success)
    {
        return Status::Error;
    }

    memcpy(stats, &stats_, sizeof(Stats));

    if (mode_ == Mode::ReadFile)
    {
        stats->hw_packets_received = stats->packets_received + stats->packets_filtered;
    }

    return Status::Success;
}

void Pcap::resetStats()
{
    memset(&stats_, 0, sizeof(Stats));

    if (handle_ && !device_.empty())
    {
        pcap_stat ps;
        memset(&ps, 0, sizeof(pcap_stat));

        if (0 == pcap_stats(handle_.get(), &ps))
        {
            recvCounter_.reset(ps.ps_recv);
            dropCounter_.reset(ps.ps_drop);
        }
    }
}

Status Pcap::startLive()
{
    handle_.reset(pcap_create(device_.c_str(), errbuf_));
    if (!handle_)
        return Status::Error;

    if (0 > pcap_set_immediate_mode(handle_, immediateMode_ ? 1 : 0) || 0 > pcap_set_snaplen(handle_, snaplen_) ||
        0 > pcap_set_promisc(handle_, promiscMode_ ? 1 : 0) || 0 > pcap_set_timeout(handle_, timeout_) ||
        0 > pcap_set_buffer_size(handle_, bufferSize_) || 0 > pcap_activate(handle_))
    {
        return Status::Error;
    }

    if (setNonBlocking(true) != Status::Success)
    {
        return Status::Error;
    }

    uint32_t localnet;
    uint32_t netmask;
    uint32_t defaultnet = 0xFFFFFF00;

    if (0 > pcap_lookupnet(device_.c_str(), &localnet, &netmask, errbuf_))
    {
        netmask = htonl(defaultnet);
    }

    netmask_ = netmask;

    return applyFilterAndFinish();
}

Status Pcap::startOffline()
{
    handle_.reset(pcap_fopen_offline(fp_, errbuf_));
    if (!handle_)
    {
        return Status::Error;
    }

    fp_ = nullptr;

    return applyFilterAndFinish();
}

Status Pcap::applyFilterAndFinish()
{
    if (!filter_.empty())
    {
        Status status = installFilter(filter_.c_str());
        if (status != Status::Success)
        {
            handle_.reset();
            return status;
        }
        filter_.clear();
    }

    resetStats();
    return Status::Success;
}

Status Pcap::setNonBlocking(bool nb)
{
    if (nb != nonblocking_)
    {
        if (0 > pcap_setnonblock(handle_.get(), nonblocking_ ? 1 : 0, errbuf_))
        {
            return Status::Error;
        }
        nonblocking_ = nb;
    }
    return Status::Success;
}

Status Pcap::installFilter(const std::string& filter)
{
    auto fcode = std::make_unique<bpf_program>();
    memset(fcode.get(), 0, sizeof(bpf_program));

    pthread_mutex_lock(&bpf_mutex);
    if (0 > pcap_compile(handle_.get(), fcode.get(), filter.c_str(), 1, netmask_))
    {
        return Status::Error;
    }
    pthread_mutex_unlock(&bpf_mutex);

    if (0 > pcap_setfilter(handle_.get(), fcode.get()))
    {
        return Status::Error;
    }
    return Status::Success;
}

Status Pcap::updateHwStats() noexcept
{
    if (!handle_ || device_.empty())
    {
        return Status::InvalidArgument;
    }

    struct pcap_stat ps;
    memset(&ps, 0, sizeof(struct pcap_stat));

    if (0 > pcap_stats(handle_.get(), &ps))
    {
        return Status::Error;
    }

    recvCounter_.update(ps.ps_recv);
    dropCounter_.update(ps.ps_drop);

    stats_.hw_packets_received = recvCounter_.getRelative();
    stats_.hw_packets_dropped = dropCounter_.getRelative();

    hwupdateCount_ = 0;
    return Status::Success;
}

} // namespace snet::driver

SNET_DLL_ALIAS(snet::driver::Pcap::create, CreateDriver)
