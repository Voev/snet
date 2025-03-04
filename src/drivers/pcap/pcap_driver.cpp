#include <errno.h>
#include <pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <snet/daq/daq.h>
#include <snet/daq/message.h>

#include "pcap_driver.hpp"
#include <snet/io/export_function.hpp>

#include <casket/utils/string.hpp>

#define DAQ_PCAP_VERSION 4

#define PCAP_DEFAULT_POOL_SIZE 16
#define DAQ_PCAP_ROLLOVER_LIM 1000000000 // Check for rollover every billionth packet

#define SET_ERROR(modinst, ...) daq_base_api.set_errbuf(modinst, __VA_ARGS__)

static SNetIO_BaseAPI_t daq_base_api;
static pthread_mutex_t bpf_mutex = PTHREAD_MUTEX_INITIALIZER;

using namespace casket::utils;

namespace snet::drivers
{

typedef struct _pcap_pkt_desc
{
    SNetIO_Message_t msg;
    DAQ_PktHdr_t pkthdr;
    uint8_t* data;
    struct _pcap_pkt_desc* next;
} PcapPktDesc;

typedef struct _pcap_msg_pool
{
    PcapPktDesc* pool;
    PcapPktDesc* freelist;
    DAQ_MsgPoolInfo_t info;
} PcapMsgPool;

struct Pcap::Impl
{
    Impl();
    ~Impl() noexcept;

    int createPacketPool(unsigned size)
    {
        PcapMsgPool* p = &pool;
        p->pool = (PcapPktDesc*)calloc(sizeof(PcapPktDesc), size);
        if (!p->pool)
        {
            SET_ERROR(modinst, "%s: Could not allocate %zu bytes for a packet descriptor pool!",
                      __func__, sizeof(PcapPktDesc) * size);
            return DAQ_ERROR_NOMEM;
        }
        p->info.mem_size = sizeof(PcapPktDesc) * size;
        while (p->info.size < size)
        {
            PcapPktDesc* desc = &p->pool[p->info.size];
            desc->data = (uint8_t*)malloc(snaplen);
            if (!desc->data)
            {
                SET_ERROR(modinst,
                          "%s: Could not allocate %d bytes for a packet descriptor message buffer!",
                          __func__, snaplen);
                return DAQ_ERROR_NOMEM;
            }
            p->info.mem_size += snaplen;

            DAQ_PktHdr_t* pkthdr = &desc->pkthdr;
            pkthdr->ingress_index = DAQ_PKTHDR_UNKNOWN;
            pkthdr->egress_index = DAQ_PKTHDR_UNKNOWN;
            pkthdr->ingress_group = DAQ_PKTHDR_UNKNOWN;
            pkthdr->egress_group = DAQ_PKTHDR_UNKNOWN;

            SNetIO_Message_t* msg = &desc->msg;
            msg->type = DAQ_MSG_TYPE_PACKET;
            msg->hdr_len = sizeof(desc->pkthdr);
            msg->hdr = &desc->pkthdr;
            msg->data = desc->data;
            msg->owner = modinst;
            msg->priv = desc;

            desc->next = p->freelist;
            p->freelist = desc;

            p->info.size++;
        }
        p->info.available = p->info.size;
        return DAQ_SUCCESS;
    }

    void destroyPacketPool() noexcept
    {
        PcapMsgPool* p = &pool;
        if (p->pool)
        {
            while (p->info.size > 0)
                free(p->pool[--p->info.size].data);
            free(p->pool);
            p->pool = NULL;
        }
        p->freelist = NULL;
        p->info.available = 0;
        p->info.mem_size = 0;
    }

    int setNonBlocking(bool nb)
    {
        if (nb != nonblocking)
        {
            int status;
            if ((status = pcap_setnonblock(handle, nonblocking ? 1 : 0, pcap_errbuf)) < 0)
            {
                SET_ERROR(modinst, "%s", pcap_errbuf);
                return status;
            }
            nonblocking = nb;
        }
        return 0;
    }

    int installFilter(const std::string& filter)
    {
        struct bpf_program fcode;

        pthread_mutex_lock(&bpf_mutex);
        if (pcap_compile(handle, &fcode, filter.c_str(), 1, netmask) < 0)
        {
            pthread_mutex_unlock(&bpf_mutex);
            SET_ERROR(modinst, "%s: pcap_compile: %s", __func__, pcap_geterr(handle));
            return DAQ_ERROR;
        }
        pthread_mutex_unlock(&bpf_mutex);

        if (pcap_setfilter(handle, &fcode) < 0)
        {
            pcap_freecode(&fcode);
            SET_ERROR(modinst, "%s: pcap_setfilter: %s", __func__, pcap_geterr(handle));
            return DAQ_ERROR;
        }

        pcap_freecode(&fcode);

        return DAQ_SUCCESS;
    }

    int updateHwStats()
    {
        struct pcap_stat ps;

        if (handle && !device.empty())
        {
            memset(&ps, 0, sizeof(struct pcap_stat));
            if (pcap_stats(handle, &ps) == -1)
            {
                SET_ERROR(modinst, "%s", pcap_geterr(handle));
                return DAQ_ERROR;
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

        return DAQ_SUCCESS;
    }

    /* Configuration */
    std::string device;
    char* filter_string;
    unsigned snaplen;
    bool promisc_mode;
    bool immediate_mode;
    int timeout;
    struct timeval timeout_tv;
    int buffer_size;
    DAQ_Mode mode;
    bool readback_timeout;
    /* State */
    SNetIO_DriverController_t* modinst;
    DAQ_Stats_t stats;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    PcapMsgPool pool;
    pcap_t* handle;
    FILE* fp;
    uint32_t netmask;
    bool nonblocking;
    volatile bool interrupted;
    /* Readback timeout state */
    struct timeval last_recv;
    PcapPktDesc* pending_desc;
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
    if (handle)
        pcap_close(handle);
    if (fp)
        fclose(fp);
    if (filter_string)
        free(filter_string);
    destroyPacketPool();
}

/*
static DAQ_VariableDesc_t pcap_variable_descriptions[] = {
    {"buffer_size", "Packet buffer space to allocate in bytes", DAQ_VAR_DESC_REQUIRES_ARGUMENT},
    {"no_promiscuous", "Disables opening the interface in promiscuous mode",
     DAQ_VAR_DESC_FORBIDS_ARGUMENT},
    {"no_immediate", "Disables immediate mode for traffic capture (may cause unbounded blocking)",
     DAQ_VAR_DESC_FORBIDS_ARGUMENT},
    {"readback_timeout", "Return timeout receive status in file readback mode",
     DAQ_VAR_DESC_FORBIDS_ARGUMENT},
};*/

/*static int pcap_daq_get_variable_descs(const DAQ_VariableDesc_t** var_desc_table)
{
    *var_desc_table = pcap_variable_descriptions;

    return sizeof(pcap_variable_descriptions) / sizeof(DAQ_VariableDesc_t);
}*/

Pcap::Impl::Impl()
    : filter_string(nullptr)
    , snaplen(0)
    , promisc_mode(false)
    , immediate_mode(false)
    , timeout(0)
    , timeout_tv()
    , buffer_size(0)
    , mode(DAQ_MODE_NONE)
    , readback_timeout(0)
    , modinst(nullptr)
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

    uint32_t pool_size = base.getMsgPoolSize();
    impl_->createPacketPool(pool_size ? pool_size : PCAP_DEFAULT_POOL_SIZE);

    impl_->mode = config.getMode();
    if (impl_->mode == DAQ_MODE_READ_FILE)
    {
        const auto fname = base.getInput();
        if (fname[0] == '-' && fname[1] == '\0')
            impl_->fp = stdin;
        else
        {
            impl_->fp = fopen(fname.c_str(), "rb");
            if (!impl_->fp)
            {
                SET_ERROR(impl_->modinst, "%s: Couldn't open file '%s' for reading: %s", __func__,
                          fname.c_str(), strerror(errno));
            }
        }
    }
    else
    {
        impl_->device = base.getInput();
        if (impl_->device.empty())
        {
            SET_ERROR(impl_->modinst, "%s: Couldn't allocate memory for the device string!",
                      __func__);
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

int Pcap::setFilter(const std::string& filter)
{
    if (impl_->handle)
    {
        int rval = impl_->installFilter(filter);
        if (rval != DAQ_SUCCESS)
            return rval;
    }
    else
    {
        pcap_t* dead_handle = pcap_open_dead(DLT_EN10MB, impl_->snaplen);
        if (!dead_handle)
        {
            SET_ERROR(impl_->modinst, "%s: Could not allocate a dead PCAP handle!", __func__);
            return DAQ_ERROR_NOMEM;
        }
        struct bpf_program fcode;
        pthread_mutex_lock(&bpf_mutex);
        if (pcap_compile(dead_handle, &fcode, filter.c_str(), 1, impl_->netmask) < 0)
        {
            pthread_mutex_unlock(&bpf_mutex);
            SET_ERROR(impl_->modinst, "%s: pcap_compile: %s", __func__, pcap_geterr(dead_handle));
            return DAQ_ERROR;
        }
        pthread_mutex_unlock(&bpf_mutex);
        pcap_freecode(&fcode);
        pcap_close(dead_handle);

        if (impl_->filter_string)
            free(impl_->filter_string);
        impl_->filter_string = strdup(filter.c_str());
        if (!impl_->filter_string)
        {
            SET_ERROR(impl_->modinst,
                      "%s: Could not allocate space to store a copy of the filter string!",
                      __func__);
            return DAQ_ERROR_NOMEM;
        }
    }

    return DAQ_SUCCESS;
}

int Pcap::start()
{
    uint32_t localnet, netmask;
    uint32_t defaultnet = 0xFFFFFF00;
    int status;

    if (!impl_->device.empty())
    {
        impl_->handle = pcap_create(impl_->device.c_str(), impl_->pcap_errbuf);
        if (!impl_->handle)
            goto fail;
        if ((status = pcap_set_immediate_mode(impl_->handle, impl_->immediate_mode ? 1 : 0)) < 0)
            goto fail;
        if ((status = pcap_set_snaplen(impl_->handle, impl_->snaplen)) < 0)
            goto fail;
        if ((status = pcap_set_promisc(impl_->handle, impl_->promisc_mode ? 1 : 0)) < 0)
            goto fail;
        if ((status = pcap_set_timeout(impl_->handle, impl_->timeout)) < 0)
            goto fail;
        if ((status = pcap_set_buffer_size(impl_->handle, impl_->buffer_size)) < 0)
            goto fail;
        if ((status = pcap_activate(impl_->handle)) < 0)
            goto fail;
        if ((status = impl_->setNonBlocking(true)) < 0)
            goto fail;
        if (pcap_lookupnet(impl_->device.c_str(), &localnet, &netmask, impl_->pcap_errbuf) < 0)
            netmask = htonl(defaultnet);
    }
    else
    {
        impl_->handle = pcap_fopen_offline(impl_->fp, impl_->pcap_errbuf);
        if (!impl_->handle)
            goto fail;
        impl_->fp = NULL;

        netmask = htonl(defaultnet);
    }
    impl_->netmask = netmask;

    if (impl_->filter_string)
    {
        if ((status = impl_->installFilter(impl_->filter_string)) != DAQ_SUCCESS)
        {
            pcap_close(impl_->handle);
            impl_->handle = NULL;
            return status;
        }
        free(impl_->filter_string);
        impl_->filter_string = NULL;
    }

    resetStats();

    return DAQ_SUCCESS;

fail:
    if (impl_->handle)
    {
        if (status == PCAP_ERROR || status == PCAP_ERROR_NO_SUCH_DEVICE ||
            status == PCAP_ERROR_PERM_DENIED)
            SET_ERROR(impl_->modinst, "%s", pcap_geterr(impl_->handle));
        else
            SET_ERROR(impl_->modinst, "%s: %s", impl_->device.c_str(), pcap_statustostr(status));
        pcap_close(impl_->handle);
        impl_->handle = NULL;
    }
    else
        SET_ERROR(impl_->modinst, "%s", impl_->pcap_errbuf);
    return DAQ_ERROR;
}

int Pcap::inject(DAQ_MsgType type, const void* hdr, const uint8_t* data, uint32_t data_len)
{
    (void)hdr;

    if (type != DAQ_MSG_TYPE_PACKET)
        return DAQ_ERROR_NOTSUP;

    if (pcap_inject(impl_->handle, data, data_len) < 0)
    {
        SET_ERROR(impl_->modinst, "%s", pcap_geterr(impl_->handle));
        return DAQ_ERROR;
    }

    impl_->stats.packets_injected++;
    return DAQ_SUCCESS;
}

int Pcap::interrupt()
{
    impl_->interrupted = true;
    return DAQ_SUCCESS;
}

int Pcap::stop()
{
    if (impl_->handle)
    {
        /* Store the hardware stats for post-stop stat calls. */
        impl_->updateHwStats();
        pcap_close(impl_->handle);
        impl_->handle = NULL;
    }

    return DAQ_SUCCESS;
}

int Pcap::getStats(DAQ_Stats_t* stats)
{
    if (impl_->updateHwStats() != DAQ_SUCCESS)
        return DAQ_ERROR;

    memcpy(stats, &impl_->stats, sizeof(DAQ_Stats_t));

    if (impl_->mode == DAQ_MODE_READ_FILE)
    {
        stats->hw_packets_received = stats->packets_received + stats->packets_filtered;
    }

    return DAQ_SUCCESS;
}

void Pcap::resetStats()
{
    struct pcap_stat ps;

    memset(&impl_->stats, 0, sizeof(DAQ_Stats_t));

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
    return DAQ_TYPE_FILE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE;
}

uint32_t Pcap::getCapabilities() const
{
    uint32_t capabilities = DAQ_CAPA_BPF | DAQ_CAPA_INTERRUPT;

    if (!impl_->device.empty())
        capabilities |= DAQ_CAPA_INJECT;
    else
        capabilities |= DAQ_CAPA_UNPRIV_START;

    return capabilities;
}

int Pcap::getDataLinkType() const
{
    if (impl_->handle)
        return pcap_datalink(impl_->handle);

    return DLT_NULL;
}

DAQ_RecvStatus Pcap::receiveMsgs(SNetIO_Message_t* msgs[], const size_t maxSize, size_t* received)
{
    struct pcap_pkthdr* pcaphdr;
    const u_char* data;
    unsigned idx;

    DAQ_RecvStatus rstat = DAQ_RSTAT_OK;
    for (idx = 0; idx < maxSize; idx++)
    {
        /* Check to see if the receive has been canceled.  If so, reset it and return appropriately.
         */
        if (impl_->interrupted)
        {
            impl_->interrupted = false;
            rstat = DAQ_RSTAT_INTERRUPTED;
            break;
        }

        /* If there is a pending descriptor from the readback timeout feature, check if it's ready
            to be realized.  If it is, finish receiving it and carry on. */
        if (impl_->pending_desc)
        {
            struct timeval delta;
            timersub(&impl_->pending_desc->pkthdr.ts, &impl_->last_recv, &delta);
            if (timercmp(&delta, &impl_->timeout_tv, >))
            {
                timeradd(&impl_->last_recv, &impl_->timeout_tv, &impl_->last_recv);
                rstat = DAQ_RSTAT_TIMEOUT;
                break;
            }
            impl_->last_recv = impl_->pending_desc->pkthdr.ts;
            impl_->pool.info.available--;
            msgs[idx] = &impl_->pending_desc->msg;
            impl_->stats.packets_received++;
            impl_->pending_desc = NULL;
            continue;
        }

        /* Make sure that we have a packet descriptor available to populate *before*
            calling into libpcap. */
        PcapPktDesc* desc = impl_->pool.freelist;
        if (!desc)
        {
            rstat = DAQ_RSTAT_NOBUF;
            break;
        }

        /* When dealing with a live interface, try to get the first packet in non-blocking mode.
            If there's nothing to receive, switch to blocking mode. */
        int pcap_rval;
        if (impl_->mode != DAQ_MODE_READ_FILE && idx == 0)
        {
            if (impl_->setNonBlocking(true) != DAQ_SUCCESS)
            {
                rstat = DAQ_RSTAT_ERROR;
                break;
            }
            pcap_rval = pcap_next_ex(impl_->handle, &pcaphdr, &data);
            if (pcap_rval == 0)
            {
                if (impl_->setNonBlocking(false) != DAQ_SUCCESS)
                {
                    rstat = DAQ_RSTAT_ERROR;
                    break;
                }
                pcap_rval = pcap_next_ex(impl_->handle, &pcaphdr, &data);
            }
        }
        else
            pcap_rval = pcap_next_ex(impl_->handle, &pcaphdr, &data);

        if (pcap_rval <= 0)
        {
            if (pcap_rval == 0)
                rstat = (idx == 0) ? DAQ_RSTAT_TIMEOUT : DAQ_RSTAT_WOULD_BLOCK;
            else if (pcap_rval == -1)
            {
                SET_ERROR(impl_->modinst, "%s", pcap_geterr(impl_->handle));
                rstat = DAQ_RSTAT_ERROR;
            }
            else if (pcap_rval == -2)
            {
                /* LibPCAP brilliantly decides to return -2 if it hit EOF in readback OR
                   pcap_breakloop() was called.  Let's try to differentiate by checking to see if we
                   asked for a break. */
                if (!impl_->interrupted && impl_->mode == DAQ_MODE_READ_FILE)
                {
                    /* Insert a final timeout receive status when readback timeout mode is enabled.
                     */
                    if (impl_->readback_timeout && !impl_->final_readback_timeout)
                    {
                        impl_->final_readback_timeout = true;
                        rstat = DAQ_RSTAT_TIMEOUT;
                    }
                    else
                        rstat = DAQ_RSTAT_EOF;
                }
                else
                {
                    impl_->interrupted = false;
                    rstat = DAQ_RSTAT_INTERRUPTED;
                }
            }
            break;
        }

        /* Update hw packet counters to make sure we detect counter overflow */
        if (++impl_->hwupdate_count == DAQ_PCAP_ROLLOVER_LIM)
            impl_->updateHwStats();

        /* Populate the packet descriptor */
        int caplen = (pcaphdr->caplen > impl_->snaplen) ? impl_->snaplen : pcaphdr->caplen;
        memcpy(desc->data, data, caplen);

        /* Next, set up the DAQ message.  Most fields are prepopulated and unchanging. */
        SNetIO_Message_t* msg = &desc->msg;
        msg->data_len = caplen;

        /* Then, set up the DAQ packet header. */
        DAQ_PktHdr_t* pkthdr = &desc->pkthdr;
        pkthdr->pktlen = pcaphdr->len;
        pkthdr->ts.tv_sec = pcaphdr->ts.tv_sec;
        pkthdr->ts.tv_usec = pcaphdr->ts.tv_usec;

        /* Last, but not least, extract this descriptor from the free list and
            place the message in the return vector. */
        impl_->pool.freelist = desc->next;
        desc->next = NULL;
        /* If the readback timeout feature is enabled, check to see if the configured timeout has
            elapsed between the previous packet and this one.  If it has, store the descriptor for
            later without modifying counters and return the timeout receive status. */
        if (impl_->mode == DAQ_MODE_READ_FILE && impl_->readback_timeout && impl_->timeout > 0)
        {
            if (timerisset(&impl_->last_recv) && timercmp(&pkthdr->ts, &impl_->last_recv, >))
            {
                struct timeval delta;
                timersub(&pkthdr->ts, &impl_->last_recv, &delta);
                if (timercmp(&delta, &impl_->timeout_tv, >))
                {
                    impl_->pending_desc = desc;
                    timeradd(&impl_->last_recv, &impl_->timeout_tv, &impl_->last_recv);
                    rstat = DAQ_RSTAT_TIMEOUT;
                    break;
                }
            }
            impl_->last_recv = pkthdr->ts;
        }
        impl_->pool.info.available--;
        msgs[idx] = &desc->msg;

        /* Finally, increment the module instance's packet counter. */
        impl_->stats.packets_received++;
    }
    *received = idx;
    return rstat;
}

int Pcap::finalizeMsg(const SNetIO_Message_t* msg, DAQ_Verdict verdict)
{
    PcapPktDesc* desc = (PcapPktDesc*)msg->priv;

    /* Sanitize the verdict. */
    if (verdict >= MAX_DAQ_VERDICT)
        verdict = DAQ_VERDICT_PASS;
    impl_->stats.verdicts[verdict]++;

    /* Toss the descriptor back on the free list for reuse. */
    desc->next = impl_->pool.freelist;
    impl_->pool.freelist = desc;
    impl_->pool.info.available++;

    return DAQ_SUCCESS;
}

int Pcap::getMsgPoolInfo(DAQ_MsgPoolInfo_t* info)
{
    *info = impl_->pool.info;

    return DAQ_SUCCESS;
}

} // namespace snet::drivers

SNET_DLL_ALIAS(snet::drivers::Pcap::create, CreateDriver)
