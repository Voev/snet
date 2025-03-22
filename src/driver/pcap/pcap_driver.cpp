#include <errno.h>
#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#include <casket/utils/string.hpp>

#include <snet/io/packet_pool.hpp>

#include "pcap_driver.hpp"
#include "pcap_handle.hpp"

#define PCAP_ROLLOVER_LIM 1000000000 // Check for rollover every billionth packet

static pthread_mutex_t bpf_mutex = PTHREAD_MUTEX_INITIALIZER;

using namespace casket::utils;

namespace snet::driver
{

struct Pcap::Impl
{
    Impl();
    ~Impl() noexcept;

    Status setNonBlocking(bool nb)
    {
        if (nb != nonblocking)
        {
            if (pcap_setnonblock(handle.get(), nonblocking ? 1 : 0, pcap_errbuf) < 0)
            {
                return Status::Error;
            }
            nonblocking = nb;
        }
        return Status::Success;
    }

    Status installFilter(const std::string& filter)
    {
        struct bpf_program fcode;

        pthread_mutex_lock(&bpf_mutex);
        if (pcap_compile(handle.get(), &fcode, filter.c_str(), 1, netmask) < 0)
        {
            pthread_mutex_unlock(&bpf_mutex);
            // SET_ERROR(modinst, "%s: pcap_compile: %s", __func__, pcap_geterr(handle));
            return Status::Error;
        }
        pthread_mutex_unlock(&bpf_mutex);

        if (pcap_setfilter(handle.get(), &fcode) < 0)
        {
            pcap_freecode(&fcode);
            // SET_ERROR(modinst, "%s: pcap_setfilter: %s", __func__, pcap_geterr(handle));
            return Status::Error;
        }

        pcap_freecode(&fcode);

        return Status::Success;
    }

    Status updateHwStats()
    {
        struct pcap_stat ps;

        if (handle && !device.empty())
        {
            memset(&ps, 0, sizeof(struct pcap_stat));
            if (pcap_stats(handle.get(), &ps) == -1)
            {
                // SET_ERROR(modinst, "%s", pcap_geterr(handle));
                return Status::Error;
            }

            if (ps.ps_recv < wrap_recv)
                rollover_recv += UINT32_MAX;

            if (ps.ps_drop < wrap_drop)
                rollover_drop += UINT32_MAX;

            wrap_recv = ps.ps_recv;
            wrap_drop = ps.ps_drop;

            stats.hw_packets_received = rollover_recv + wrap_recv - base_recv;
            stats.hw_packets_dropped = rollover_drop + wrap_drop - base_drop;
            hwupdate_count = 0;
        }

        return Status::Success;
    }

    /* Configuration */
    io::PacketPool<io::RawPacket> pool;
    std::string device;
    std::string filter_string;
    unsigned snaplen;
    bool promisc_mode;
    bool immediate_mode;
    int timeout;
    struct timeval timeout_tv;
    int buffer_size;
    Mode mode;
    bool readback_timeout;
    /* State */
    Stats stats;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    PcapHandle handle;
    FILE* fp;
    uint32_t netmask;
    bool nonblocking;
    volatile bool interrupted;
    /* Readback timeout state */
    struct timeval last_recv;
    bool final_readback_timeout;
    /* Stats tracking */
    uint32_t base_recv;
    uint32_t base_drop;
    uint64_t rollover_recv;
    uint64_t rollover_drop;
    uint32_t wrap_recv;
    uint32_t wrap_drop;
    uint32_t hwupdate_count;
};

Pcap::Impl::~Impl()
{
    handle.reset();

    if (fp)
        fclose(fp);
}

Pcap::Impl::Impl()
    : snaplen(0)
    , promisc_mode(false)
    , immediate_mode(false)
    , timeout(0)
    , timeout_tv()
    , buffer_size(0)
    , mode(Mode::None)
    , readback_timeout(0)
    , stats()
    , handle(nullptr)
    , fp(nullptr)
    , netmask(0)
    , nonblocking(false)
    , interrupted(false)
    , last_recv()
    , final_readback_timeout(false)
    , base_recv(0)
    , base_drop(0)
    , rollover_recv(0)
    , rollover_drop(0)
    , wrap_recv(0)
    , wrap_drop(0)
    , hwupdate_count(0)
{
}

Pcap::Pcap(const io::DriverConfig& config)
    : impl_(std::make_unique<Pcap::Impl>())
{
    const auto& base = config.getConfig();
    impl_->snaplen = base.getSnaplen();
    impl_->timeout = base.getTimeout();
    impl_->timeout_tv.tv_sec = impl_->timeout / 1000;
    impl_->timeout_tv.tv_usec = (impl_->timeout % 1000) * 1000;
    impl_->promisc_mode = true;
    impl_->immediate_mode = true;
    impl_->readback_timeout = false;

    for (const auto& [name, value] : config.getParameters())
    {
        if (iequals(name, "buffer_size"))
            impl_->buffer_size = strtol(value.c_str(), NULL, 10);
        else if (iequals(name, "no_promiscuous"))
            impl_->promisc_mode = false;
        else if (iequals(name, "no_immediate"))
            impl_->immediate_mode = false;
        else if (iequals(name, "readback_timeout"))
            impl_->readback_timeout = true;
    }

    impl_->pool.allocatePool(16);
    impl_->mode = config.getMode();
    if (impl_->mode == Mode::ReadFile)
    {
        const auto fname = base.getInput();
        if (fname[0] == '-' && fname[1] == '\0')
            impl_->fp = stdin;
        else
        {
            impl_->fp = fopen(fname.c_str(), "rb");
            if (!impl_->fp)
            {
                // SET_ERROR(impl_->modinst, "%s: Couldn't open file '%s' for reading: %s",
                // __func__,
                //           fname.c_str(), strerror(errno));
            }
        }
    }
    else
    {
        impl_->device = base.getInput();
        if (impl_->device.empty())
        {
            // SET_ERROR(impl_->modinst, "%s: Couldn't allocate memory for the device string!",
            //           __func__);
        }
    }

    impl_->hwupdate_count = 0;
}

std::shared_ptr<io::Driver> Pcap::create(const io::DriverConfig& config)
{
    return std::make_shared<Pcap>(config);
}

Pcap::~Pcap() noexcept
{
    impl_.reset();
}

Status Pcap::setFilter(const std::string& filter)
{
    if (impl_->handle)
    {
        auto status = impl_->installFilter(filter);
        if (status != Status::Success)
            return status;
    }
    else
    {
        pcap_t* dead_handle = pcap_open_dead(DLT_EN10MB, impl_->snaplen);
        if (!dead_handle)
        {
            // SET_ERROR(impl_->modinst, "%s: Could not allocate a dead PCAP handle!", __func__);
            // return DAQ_ERROR_NOMEM;
        }
        struct bpf_program fcode;
        pthread_mutex_lock(&bpf_mutex);
        if (pcap_compile(dead_handle, &fcode, filter.c_str(), 1, impl_->netmask) < 0)
        {
            pthread_mutex_unlock(&bpf_mutex);
            // SET_ERROR(impl_->modinst, "%s: pcap_compile: %s", __func__,
            // pcap_geterr(dead_handle));
            return Status::Error;
        }
        pthread_mutex_unlock(&bpf_mutex);
        pcap_freecode(&fcode);
        pcap_close(dead_handle);

        impl_->filter_string = filter;
    }

    return Status::Success;
}

Status Pcap::start()
{
    uint32_t localnet, netmask;
    uint32_t defaultnet = 0xFFFFFF00;
    Status status;

    if (!impl_->device.empty())
    {
        impl_->handle.reset(pcap_create(impl_->device.c_str(), impl_->pcap_errbuf));
        if (!impl_->handle)
            goto fail;
        if (pcap_set_immediate_mode(impl_->handle, impl_->immediate_mode ? 1 : 0) < 0)
            goto fail;
        if (pcap_set_snaplen(impl_->handle, impl_->snaplen) < 0)
            goto fail;
        if (pcap_set_promisc(impl_->handle, impl_->promisc_mode ? 1 : 0) < 0)
            goto fail;
        if (pcap_set_timeout(impl_->handle, impl_->timeout) < 0)
            goto fail;
        if (pcap_set_buffer_size(impl_->handle, impl_->buffer_size) < 0)
            goto fail;
        if (pcap_activate(impl_->handle) < 0)
            goto fail;
        if (impl_->setNonBlocking(true) != Status::Success)
            goto fail;
        if (pcap_lookupnet(impl_->device.c_str(), &localnet, &netmask, impl_->pcap_errbuf) < 0)
            netmask = htonl(defaultnet);
    }
    else
    {
        impl_->handle.reset(pcap_fopen_offline(impl_->fp, impl_->pcap_errbuf));
        if (!impl_->handle)
            goto fail;
        impl_->fp = NULL;

        netmask = htonl(defaultnet);
    }
    impl_->netmask = netmask;

    if (!impl_->filter_string.empty())
    {
        if ((status = impl_->installFilter(impl_->filter_string.c_str())) != Status::Success)
        {
            pcap_close(impl_->handle);
            impl_->handle = NULL;
            return status;
        }
        impl_->filter_string.clear();
    }

    resetStats();

    return Status::Success;

fail:
    impl_->handle.reset();
    return Status::Error;
}

Status Pcap::inject(const uint8_t* data, uint32_t data_len)
{
    if (pcap_inject(impl_->handle, data, data_len) < 0)
    {
        return Status::Error;
    }

    impl_->stats.packets_injected++;
    return Status::Success;
}

Status Pcap::interrupt()
{
    impl_->interrupted = true;
    return Status::Success;
}

Status Pcap::stop()
{
    if (impl_->handle)
    {
        /* Store the hardware stats for post-stop stat calls. */
        impl_->updateHwStats();
        impl_->handle.reset();
    }

    return Status::Success;
}

Status Pcap::getStats(Stats* stats)
{
    if (impl_->updateHwStats() != Status::Success)
        return Status::Error;

    memcpy(stats, &impl_->stats, sizeof(Stats));

    if (impl_->mode == Mode::ReadFile)
    {
        stats->hw_packets_received = stats->packets_received + stats->packets_filtered;
    }

    return Status::Success;
}

void Pcap::resetStats()
{
    struct pcap_stat ps;

    memset(&impl_->stats, 0, sizeof(Stats));

    if (!impl_->handle)
        return;

    memset(&ps, 0, sizeof(struct pcap_stat));
    if (impl_->handle && !impl_->device.empty() && pcap_stats(impl_->handle, &ps) == 0)
    {
        impl_->base_recv = impl_->wrap_recv = ps.ps_recv;
        impl_->base_drop = impl_->wrap_drop = ps.ps_drop;
    }
}

int Pcap::getSnaplen() const
{
    return impl_->snaplen;
}

uint32_t Pcap::getType() const
{
    return 0;
}

uint32_t Pcap::getCapabilities() const
{
    uint32_t capabilities{0};
    return capabilities;
}

io::LinkLayerType Pcap::getDataLinkType() const
{
    if (impl_->handle)
        return static_cast<io::LinkLayerType>(pcap_datalink(impl_->handle));
    return io::LINKTYPE_NULL;
}

RecvStatus Pcap::receivePacket(io::RawPacket** pRawPacket)
{
    RecvStatus rstat{RecvStatus::Ok};
    struct pcap_pkthdr* pcaphdr;
    const u_char* data;

    if (impl_->interrupted)
    {
        impl_->interrupted = false;
        return RecvStatus::Interrupted;
    }

    /* When dealing with a live interface, try to get the first packet in non-blocking mode.
            If there's nothing to receive, switch to blocking mode. */
    int pcap_rval;
    if (impl_->mode != Mode::ReadFile)
    {
        if (impl_->setNonBlocking(true) != Status::Success)
        {
            rstat = RecvStatus::Error;
        }
        else
        {
            pcap_rval = pcap_next_ex(impl_->handle, &pcaphdr, &data);
            if (pcap_rval == 0)
            {
                if (impl_->setNonBlocking(false) != Status::Success)
                {
                    rstat = RecvStatus::Error;
                }
                else
                {
                    pcap_rval = pcap_next_ex(impl_->handle, &pcaphdr, &data);
                }
            }
        }
    }
    else
        pcap_rval = pcap_next_ex(impl_->handle, &pcaphdr, &data);

    if (pcap_rval <= 0)
    {
        if (pcap_rval == 0)
            rstat = RecvStatus::Timeout;
        else if (pcap_rval == -1)
        {
            // SET_ERROR(impl_->modinst, "%s", pcap_geterr(impl_->handle));
            rstat = RecvStatus::Error;
        }
        else if (pcap_rval == -2)
        {
            /* LibPCAP brilliantly decides to return -2 if it hit EOF in readback OR
               pcap_breakloop() was called.  Let's try to differentiate by checking to see if we
               asked for a break. */
            if (!impl_->interrupted && impl_->mode == Mode::ReadFile)
            {
                /* Insert a final timeout receive status when readback timeout mode is enabled.
                 */
                if (impl_->readback_timeout && !impl_->final_readback_timeout)
                {
                    impl_->final_readback_timeout = true;
                    rstat = RecvStatus::Timeout;
                }
                else
                    rstat = RecvStatus::Eof;
            }
            else
            {
                impl_->interrupted = false;
                rstat = RecvStatus::Interrupted;
            }
        }
    }

    /* Update hw packet counters to make sure we detect counter overflow */
    if (++impl_->hwupdate_count == PCAP_ROLLOVER_LIM)
        impl_->updateHwStats();

    auto rawPacket = impl_->pool.acquirePacket();

    struct timeval ts{};
    ts.tv_sec = pcaphdr->ts.tv_sec;
    ts.tv_usec = pcaphdr->ts.tv_usec;

    int caplen = (pcaphdr->caplen > impl_->snaplen) ? impl_->snaplen : pcaphdr->caplen;

    if (!rawPacket->setRawData(data, caplen, ts, getDataLinkType()))
    {
        rstat = RecvStatus::Error;
    }
    else
    {
        impl_->stats.packets_received++;
    }

    *pRawPacket = rawPacket;

    return rstat;
}

Status Pcap::finalizePacket(io::RawPacket* rawPacket, Verdict verdict)
{
    if (verdict >= MAX_Verdict)
        verdict = Verdict_PASS;
    impl_->stats.verdicts[verdict]++;
    rawPacket->clear();
    impl_->pool.releasePacket(rawPacket);

    return Status::Success;
}

Status Pcap::getMsgPoolInfo(PacketPoolInfo* info)
{
    (void)info;
    return Status::Success;
}

} // namespace snet::driver

SNET_DLL_ALIAS(snet::driver::Pcap::create, CreateDriver)
