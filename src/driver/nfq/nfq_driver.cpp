
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <system_error>

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include <libmnl/libmnl.h>

#include <snet/io/packet_pool.hpp>
#include <snet/socket.hpp>

#include <snet/utils/endianness.hpp>
#include <casket/utils/string.hpp>
#include <casket/utils/error_code.hpp>
#include <casket/utils/to_number.hpp>

#include "nfq_driver.hpp"
#include "nfq_packet.hpp"

using namespace casket::utils;
using namespace snet::socket;

namespace snet::driver
{

#define NFQ_DEFAULT_POOL_SIZE 16
#define DEFAULT_QUEUE_MAXLEN 1024 // Based on NFQNL_QMAX_DEFAULT from nfnetlnk_queue_core.c

constexpr size_t align_length(size_t len, size_t alignment = 4) noexcept
{
    return (len + alignment - 1) & ~(alignment - 1);
}

void* get_payload(const nlmsghdr* nlh)
{
    return (uint8_t*)nlh + align_length(sizeof(nlmsghdr));
}

void* get_payload_offset(const nlmsghdr* nlh, size_t offset)
{
    return (uint8_t*)nlh + align_length(sizeof(nlmsghdr)) + align_length(offset);
}

void* get_payload_tail(const nlmsghdr* nlh)
{
    return (uint8_t*)nlh + align_length(nlh->nlmsg_len);
}

uint16_t attr_get_payload_len(const struct nlattr* attr)
{
    return attr->nla_len - align_length(sizeof(nlattr));
}

void* attr_get_payload(const struct nlattr* attr)
{
    return (uint8_t*)attr + align_length(sizeof(nlattr));
}

uint32_t attr_get_u32(const struct nlattr* attr)
{
    return *((uint32_t*)attr_get_payload(attr));
}

static inline nlmsghdr* CreateNetfilterHeader(void* buf, int type, uint32_t queue_num)
{
    auto len = align_length(sizeof(nlmsghdr));
    nlmsghdr* nlh = static_cast<nlmsghdr*>(buf);
    std::memset(buf, 0, len);

    nlh->nlmsg_len = len;
    nlh->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | type;
    nlh->nlmsg_flags = NLM_F_REQUEST;

    len = align_length(sizeof(nfgenmsg));
    char* ptr = (char*)nlh + nlh->nlmsg_len;
    nlh->nlmsg_len += len;
    std::memset(ptr, 0, len);

    nfgenmsg* nfg = reinterpret_cast<nfgenmsg*>(ptr);
    nfg->nfgen_family = AF_UNSPEC;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = htons(queue_num);

    return nlh;
}

void attr_put(struct nlmsghdr* nlh, uint16_t type, size_t len, const void* data)
{
    nlattr* attr = (nlattr*)get_payload_tail(nlh);
    uint16_t payload_len = align_length(sizeof(nlattr)) + len;
    int pad;

    attr->nla_type = type;
    attr->nla_len = payload_len;

    memcpy((uint8_t*)attr + align_length(sizeof(nlattr)), data, len);
    pad = MNL_ALIGN(len) - len;
    if (pad > 0)
        memset((uint8_t*)attr + align_length(sizeof(nlattr)) + len, 0, pad);

    nlh->nlmsg_len += MNL_ALIGN(payload_len);
}

static nlmsghdr* nfq_build_cfg_command(char* buf, uint16_t pf, uint8_t command, int queue_num)
{
    nlmsghdr* nlh = CreateNetfilterHeader(buf, NFQNL_MSG_CONFIG, queue_num);
    nfqnl_msg_config_cmd cmd;
    cmd.command = command;
    cmd.pf = htons(pf);

    attr_put(nlh, NFQA_CFG_CMD, sizeof(cmd), &cmd);
    return nlh;
}

static nlmsghdr* nfq_build_cfg_params(char* buf, uint8_t mode, int range, int queue_num)
{
    nlmsghdr* nlh = CreateNetfilterHeader(buf, NFQNL_MSG_CONFIG, queue_num);
    nfqnl_msg_config_params params;
    params.copy_range = htonl(range);
    params.copy_mode = mode;

    attr_put(nlh, NFQA_CFG_PARAMS, sizeof(params), &params);
    return nlh;
}

static nlmsghdr* nfq_build_verdict(char* buf, int id, int queue_num, int verd, uint32_t plen,
                                   uint8_t* pkt)
{
    nlmsghdr* nlh = CreateNetfilterHeader(buf, NFQNL_MSG_VERDICT, queue_num);
    nfqnl_msg_verdict_hdr verdictHeader;
    verdictHeader.verdict = htonl(verd);
    verdictHeader.id = htonl(id);

    attr_put(nlh, NFQA_VERDICT_HDR, sizeof(verdictHeader), &verdictHeader);
    if (plen)
        attr_put(nlh, NFQA_PAYLOAD, plen, pkt);

    return nlh;
}

static int parse_attr_cb(const nlattr* attr, void* data)
{
    const nlattr** tb = (const nlattr**)data;
    int type = attr->nla_type & NLA_TYPE_MASK;

    /* skip unsupported attribute in user-space */
    if (type > NFQA_MAX)
        return MNL_CB_OK;

    switch (type)
    {
    case NFQA_MARK:
    case NFQA_IFINDEX_INDEV:
    case NFQA_IFINDEX_OUTDEV:
    case NFQA_IFINDEX_PHYSINDEV:
    case NFQA_IFINDEX_PHYSOUTDEV:
    case NFQA_CAP_LEN:
    case NFQA_SKB_INFO:
    case NFQA_SECCTX:
    case NFQA_UID:
    case NFQA_GID:
    case NFQA_CT_INFO:
        if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
            return -1;
        break;
    case NFQA_TIMESTAMP:
        if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC, sizeof(nfqnl_msg_packet_timestamp)) < 0)
        {
            return -1;
        }
        break;
    case NFQA_HWADDR:
        if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC, sizeof(nfqnl_msg_packet_hw)) < 0)
        {
            return -1;
        }
        break;
    case NFQA_PACKET_HDR:
        if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC, sizeof(nfqnl_msg_packet_hdr)) < 0)
        {
            return -1;
        }
        break;
    case NFQA_PAYLOAD:
    case NFQA_CT:
    case NFQA_EXP:
        break;
    }
    tb[type] = attr;
    return MNL_CB_OK;
}

bool nlmsg_ok(const nlmsghdr* nlh, int len)
{
    return len >= (int)sizeof(nlmsghdr) && nlh->nlmsg_len >= sizeof(nlmsghdr) &&
           (int)nlh->nlmsg_len <= len;
}

nlmsghdr* nlmsg_next(const nlmsghdr* nlh, int* len)
{
    *len -= align_length(nlh->nlmsg_len);
    return (nlmsghdr*)((uint8_t*)nlh + align_length(nlh->nlmsg_len));
}

bool attr_ok(const nlattr* attr, int len)
{
    return len >= (int)sizeof(struct nlattr) && attr->nla_len >= sizeof(struct nlattr) &&
           (int)attr->nla_len <= len;
}

struct nlattr* attr_next(const nlattr* attr)
{
    return (nlattr*)((uint8_t*)attr + align_length(attr->nla_len));
}

int attr_parse(const nlmsghdr* nlh, unsigned int offset, void* data)
{
    int ret = MNL_CB_OK;
    const struct nlattr* attr;

    for (attr = (nlattr*)get_payload_offset(nlh, offset);
         attr_ok(attr, (char*)get_payload_tail(nlh) - (char*)(attr)); attr = attr_next(attr))
    {
        if ((ret = parse_attr_cb(attr, data)) <= 0)
            return ret;
    }
    return ret;
}

static int process_message_cb(const nlmsghdr* nlh, void* data)
{
    auto rawPacket = static_cast<NfqRawPacket*>(data);
    nlattr* attr[NFQA_MAX + 1] = {};
    int ret;

    /* FIXIT-L In the event that there is actually more than one packet per message, handle it
       gracefully. I haven't actually seen this happen yet. */
    if (rawPacket->mh)
        return -1;

    /* Parse the message attributes */
    if ((ret = attr_parse(nlh, sizeof(nfgenmsg), attr)) != MNL_CB_OK)
        return ret;

    /* Populate the packet descriptor */
    rawPacket->mh = nlh;
    rawPacket->ph = (nfqnl_msg_packet_hdr*)attr_get_payload(attr[NFQA_PACKET_HDR]);

    timeval tv{};
    gettimeofday(&tv, NULL);

    size_t pktlen;
    size_t framelen = attr_get_payload_len(attr[NFQA_PAYLOAD]);
    if (attr[NFQA_CAP_LEN])
        pktlen = ntohl(attr_get_u32(attr[NFQA_CAP_LEN]));
    else
        pktlen = framelen;

    rawPacket->setRawData((uint8_t*)attr_get_payload(attr[NFQA_PAYLOAD]), pktlen, tv,
                          io::LINKTYPE_RAW, framelen);

    return MNL_CB_OK;
}

int cb_run_my(const void* buf, size_t numbytes, unsigned int seq, unsigned int portid, void* data)
{
    int ret = MNL_CB_OK, len = numbytes;
    const struct nlmsghdr* nlh = (struct nlmsghdr*)buf;

    while (nlmsg_ok(nlh, len))
    {
        /* check message source */
        auto v = nlh->nlmsg_pid && portid ? nlh->nlmsg_pid == portid : true;
        if (!v)
        {
            errno = ESRCH;
            return -1;
        }
        /* perform sequence tracking */
        v = nlh->nlmsg_seq && seq ? nlh->nlmsg_seq == seq : true;
        if (!v)
        {
            errno = EPROTO;
            return -1;
        }

        /* dump was interrupted */
        if (nlh->nlmsg_flags & NLM_F_DUMP_INTR)
        {
            errno = EINTR;
            return -1;
        }

        /* netlink data message handling */
        if (nlh->nlmsg_type >= NLMSG_MIN_TYPE)
        {
            ret = process_message_cb(nlh, data);
            if (ret <= 0)
                goto out;
        }
        else if (nlh->nlmsg_type == NLMSG_ERROR)
        {
            const struct nlmsgerr* err = (struct nlmsgerr*)get_payload(nlh);

            if (nlh->nlmsg_len < sizeof(nlmsgerr) + align_length(sizeof(nlmsghdr)))
            {
                errno = EBADMSG;
                return -1;
            }
            /* Netlink subsystems returns the errno value with different signess */
            if (err->error < 0)
                errno = -err->error;
            else
                errno = err->error;

            return err->error == 0 ? 0 : -1;
        }
        else
        {
            ret = 0;
            goto out;
        }
        nlh = nlmsg_next(nlh, &len);
    }
out:
    return ret;
}

struct NfQueue::Impl
{
    Impl();
    ~Impl() noexcept;

    ssize_t socket_sendto(const void* buf, size_t len)
    {
        sockaddr_nl snl{};
        snl.nl_family = AF_NETLINK;
        return ::sendto(socket, buf, len, 0, (sockaddr*)&snl, sizeof(snl));
    }

    ssize_t socket_recv(void* buf, size_t bufsiz, bool blocking, std::error_code& ec)
    {
        ec.clear();

        sockaddr_nl address;
        ssize_t ret;

        iovec iov = {
            .iov_base = buf,
            .iov_len = bufsiz,
        };
        msghdr msg = {
            .msg_name = &address,
            .msg_namelen = sizeof(address),
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = NULL,
            .msg_controllen = 0,
            .msg_flags = 0,
        };

        ret = ::recvmsg(socket, &msg, blocking ? 0 : MSG_DONTWAIT);
        if (ret == -1)
        {
            ec = GetLastSystemError();
            return ret;
        }

        if (msg.msg_flags & MSG_TRUNC)
        {
            ec = std::make_error_code(std::errc::no_space_on_device);
            return -1;
        }
        if (msg.msg_namelen != sizeof(sockaddr_nl))
        {
            ec = std::make_error_code(std::errc::invalid_argument);
            return -1;
        }

        return ret;
    }

    void bindAddress(unsigned int groups, pid_t pid, std::error_code& ec) noexcept
    {
        address.nl_family = AF_NETLINK;
        address.nl_groups = groups;
        address.nl_pid = pid;

        int ret = ::bind(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address));
        if (ret < 0)
        {
            ec = GetLastSystemError();
            return;
        }

        socklen_t addressLength = sizeof(address);
        ret = getsockname(socket, reinterpret_cast<sockaddr*>(&address), &addressLength);
        if (ret < 0)
        {
            ec = GetLastSystemError();
            return;
        }

        if (addressLength != sizeof(address) || address.nl_family != AF_NETLINK)
        {
            ec = std::make_error_code(std::errc::invalid_argument);
        }
    }

    void closeSocket() noexcept
    {
        if (socket != InvalidSocket)
        {
            CloseSocket(socket);
            socket = InvalidSocket;
        }
    }

    /* Configuration */
    unsigned queue_num;
    int snaplen;
    int timeout;
    unsigned queue_maxlen;
    bool fail_open;
    /* State */
    io::PacketPool<NfqRawPacket> pool;
    char* nlmsg_buf;
    size_t nlmsg_bufsize;
    socket::SocketType socket;
    sockaddr_nl address;
    unsigned portid;
    volatile bool interrupted;
};

NfQueue::Impl::~Impl()
{
    closeSocket();

    if (nlmsg_buf)
        free(nlmsg_buf);
}

NfQueue::Impl::Impl()
    : queue_num(0)
    , snaplen(0)
    , timeout(0)
    , queue_maxlen(0)
{
}

NfQueue::NfQueue(const io::DriverConfig& config)
    : impl_(std::make_unique<NfQueue::Impl>())
{
    std::error_code ec;

    const auto& base = config.getConfig();
    impl_->snaplen = base.getSnaplen();
    impl_->timeout = base.getTimeout();
    impl_->queue_maxlen = DEFAULT_QUEUE_MAXLEN;

    casket::utils::to_number(base.getInput(), impl_->queue_num, ec);

    for (const auto& [name, value] : config.getParameters())
    {
        if (iequals(name, "fail_open"))
            impl_->fail_open = false;
        else if (iequals(name, "queue_maxlen"))
            casket::utils::to_number(value, impl_->queue_maxlen, ec);
    }

    impl_->nlmsg_bufsize = impl_->snaplen + MNL_SOCKET_BUFFER_SIZE;

    /* Allocate a scratch buffer for general usage by the context (basically for anything that's not
        receiving a packet) */
    impl_->nlmsg_buf = (char*)malloc(impl_->nlmsg_bufsize);

    impl_->pool.allocatePool(NFQ_DEFAULT_POOL_SIZE);
    impl_->socket = socket::CreateSocket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER, ec);

    /* Implement the requested timeout by way of the receive timeout on the netlink socket */
    impl_->timeout = base.getTimeout();
    if (impl_->timeout)
    {
        timeval tv;
        tv.tv_sec = impl_->timeout / 1000;
        tv.tv_usec = (impl_->timeout % 1000) * 1000;
        setsockopt(impl_->socket, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv));
    }

    /* Set the socket receive buffer to something reasonable based on the desired queue and capture
       lengths. Try with FORCE first to allow overriding the system's global rmem_max, then fall
       back on being limited by it if that doesn't work. The value will be doubled to allow room for
       bookkeeping overhead, so the default of 1024 * 1500 will end up allocating about 3MB of
       receive buffer space.  The unmodified default tends to be around 208KB. */
    unsigned int socket_rcvbuf_size = impl_->queue_maxlen * impl_->snaplen;
    if (setsockopt(impl_->socket, SOL_SOCKET, SO_RCVBUFFORCE, &socket_rcvbuf_size,
                   sizeof(socket_rcvbuf_size)) == -1)
    {
        setsockopt(impl_->socket, SOL_SOCKET, SO_RCVBUF, &socket_rcvbuf_size,
                   sizeof(socket_rcvbuf_size));
    }

    impl_->bindAddress(0, 0, ec);

    nlmsghdr* nlh;

    /* The following four packet family unbind/bind commands do nothing on modern (3.8+) kernels.
        They used to handle binding the netfilter socket to a particular address family. */
    nlh = nfq_build_cfg_command(impl_->nlmsg_buf, AF_INET, NFQNL_CFG_CMD_PF_UNBIND, 0);
    impl_->socket_sendto(nlh, nlh->nlmsg_len);

    nlh = nfq_build_cfg_command(impl_->nlmsg_buf, AF_INET6, NFQNL_CFG_CMD_PF_UNBIND, 0);
    impl_->socket_sendto(nlh, nlh->nlmsg_len);

    nlh = nfq_build_cfg_command(impl_->nlmsg_buf, AF_INET, NFQNL_CFG_CMD_PF_BIND, 0);
    impl_->socket_sendto(nlh, nlh->nlmsg_len);

    nlh = nfq_build_cfg_command(impl_->nlmsg_buf, AF_INET6, NFQNL_CFG_CMD_PF_BIND, 0);
    impl_->socket_sendto(nlh, nlh->nlmsg_len);

    /* Now, actually bind to the netfilter queue.  The address family specified is irrelevant. */
    nlh = nfq_build_cfg_command(impl_->nlmsg_buf, AF_UNSPEC, NFQNL_CFG_CMD_BIND, impl_->queue_num);
    impl_->socket_sendto(nlh, nlh->nlmsg_len);

    /*
     * Set the queue into packet copying mode with a max copying length of our snaplen.
     * While we're building a configuration message, we might as well tack on our requested
     * maximum queue length and enable delivery of packets that will be subject to GSO. That
     * last bit means we'll potentially see packets larger than the device MTU prior to their
     * trip through the segmentation offload path.  They'll probably show up as truncated.
     */
    nlh =
        nfq_build_cfg_params(impl_->nlmsg_buf, NFQNL_COPY_PACKET, impl_->snaplen, impl_->queue_num);

    uint32_t value = htonl(impl_->queue_maxlen);
    attr_put(nlh, NFQA_CFG_QUEUE_MAXLEN, sizeof(value), &value);

    value = htonl(NFQA_CFG_F_GSO);
    attr_put(nlh, NFQA_CFG_FLAGS, sizeof(value), &value);
    attr_put(nlh, NFQA_CFG_MASK, sizeof(value), &value);

    if (impl_->fail_open)
    {
        value = htonl(NFQA_CFG_F_FAIL_OPEN);
        attr_put(nlh, NFQA_CFG_FLAGS, sizeof(value), &value);
        attr_put(nlh, NFQA_CFG_MASK, sizeof(value), &value);
    }

    impl_->socket_sendto(nlh, nlh->nlmsg_len);
}

std::shared_ptr<io::Driver> NfQueue::create(const io::DriverConfig& config)
{
    return std::make_shared<NfQueue>(config);
}

NfQueue::~NfQueue() noexcept
{
    impl_.reset();
}

Status NfQueue::start()
{
    return Status::Success;
}

Status NfQueue::interrupt()
{
    impl_->interrupted = true;
    return Status::Success;
}

Status NfQueue::stop()
{
    nlmsghdr* nlh =
        nfq_build_cfg_command(impl_->nlmsg_buf, AF_INET, NFQNL_CFG_CMD_UNBIND, impl_->queue_num);
    if (impl_->socket_sendto(nlh, nlh->nlmsg_len) == -1)
    {
        return Status::Error;
    }

    impl_->closeSocket();
    return Status::Success;
}

int NfQueue::getSnaplen() const
{
    return impl_->snaplen;
}

uint32_t NfQueue::getType() const
{
    return 0;
}

uint32_t NfQueue::getCapabilities() const
{
    uint32_t capabilities{0};
    return capabilities;
}

io::LinkLayerType NfQueue::getDataLinkType() const
{
    return io::LINKTYPE_RAW;
}

RecvStatus NfQueue::receivePacket(io::RawPacket** pRawPacket)
{
    RecvStatus rstat{RecvStatus::Ok};
    std::error_code ec;

    if (pRawPacket == nullptr)
    {
        return RecvStatus::Error;
    }

    if (impl_->interrupted)
    {
        impl_->interrupted = false;
        return RecvStatus::Interrupted;
    }

    /* Make sure that we have a packet descriptor available to populate. */
    NfqRawPacket* rawPacket = impl_->pool.acquirePacket();
    if (!rawPacket)
    {
        return RecvStatus::Error;
    }

    rawPacket->nlmsg_buf = new uint8_t[impl_->nlmsg_bufsize];

    ssize_t ret;
    do
    {
        ret = impl_->socket_recv(rawPacket->nlmsg_buf, impl_->nlmsg_bufsize, true, ec);
        if (ret < 0)
        {
            if (ec == std::errc::no_buffer_space)
            {
                continue;
            }
            else if (ec == std::errc::resource_unavailable_try_again ||
                     ec == std::errc::operation_would_block)
            {
                rstat = RecvStatus::Interrupted;
            }
            else if (ec == std::errc::interrupted)
            {
                if (!impl_->interrupted)
                {
                    continue;
                }
                impl_->interrupted = false;
                rstat = RecvStatus::Interrupted;
            }
            else
            {
                rstat = RecvStatus::Error;
            }
            break;
        }

        ret = cb_run_my(rawPacket->nlmsg_buf, ret, 0, impl_->portid, rawPacket);
        if (ret < 0)
        {
            rstat = RecvStatus::Error;
        }
        else
        {
            *pRawPacket = rawPacket;
        }

    } while (false);

    return rstat;
}

Status NfQueue::finalizePacket(io::RawPacket* rawPacket, Verdict verdict)
{

    /* Send the verdict back to the kernel through netlink */
    /* FIXIT-L Consider using an iovec for scatter/gather transmission with the new payload as a
        separate entry. This would avoid a copy and potentially avoid buffer size restrictions.
        Only as relevant as REPLACE is common. */
    uint32_t plen = (verdict == Verdict::Verdict_REPLACE) ? rawPacket->getRawDataLen() : 0;
    int nfq_verdict = (verdict == Verdict::Verdict_PASS || verdict == Verdict::Verdict_REPLACE)
                          ? NF_ACCEPT
                          : NF_DROP;

    auto nlPacket = dynamic_cast<NfqRawPacket*>(rawPacket);

    nlmsghdr* nlh =
        nfq_build_verdict(impl_->nlmsg_buf, ntohl(nlPacket->ph->packet_id), impl_->queue_num,
                          nfq_verdict, plen, (uint8_t*)rawPacket->getRawData());
    if (impl_->socket_sendto(nlh, nlh->nlmsg_len) == -1)
    {
        return Status::Error;
    }

    nlPacket->mh = nullptr;
    nlPacket->ph = nullptr;

    impl_->pool.releasePacket(nlPacket);

    return Status::Success;
}

} // namespace snet::driver

SNET_DLL_ALIAS(snet::driver::NfQueue::create, CreateDriver)
