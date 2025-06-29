

#include <system_error>

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include <snet/io/packet_pool.hpp>
#include <snet/socket.hpp>

#include <casket/utils/endianness.hpp>
#include <casket/utils/string.hpp>
#include <casket/utils/error_code.hpp>
#include <casket/utils/to_number.hpp>

#include "nfq_driver.hpp"
#include "nfq_packet.hpp"

using namespace casket;
using namespace snet::socket;

static constexpr std::size_t kDefaultPoolSize{16};
static constexpr std::size_t kDefaultQueueMaxLength{16};

namespace snet::driver
{

inline constexpr size_t align_length(size_t len, size_t alignment = 4) noexcept
{
    return (len + alignment - 1) & ~(alignment - 1);
}

inline bool MessageIsOk(const nlmsghdr* nlh, int len)
{
    return len >= (int)sizeof(nlmsghdr) && nlh->nlmsg_len >= sizeof(nlmsghdr) &&
           (int)nlh->nlmsg_len <= len;
}

inline nlmsghdr* MessageNext(const nlmsghdr* nlh, int* len)
{
    *len -= align_length(nlh->nlmsg_len);
    return (nlmsghdr*)((uint8_t*)nlh + align_length(nlh->nlmsg_len));
}

inline void* MessageGetPayload(const nlmsghdr* nlh)
{
    return (uint8_t*)nlh + align_length(sizeof(nlmsghdr));
}

inline void* MessageGetPayloadOffset(const nlmsghdr* nlh, size_t offset)
{
    return (uint8_t*)nlh + align_length(sizeof(nlmsghdr)) + align_length(offset);
}

inline void* MessageGetPayloadTail(const nlmsghdr* nlh)
{
    return (uint8_t*)nlh + align_length(nlh->nlmsg_len);
}

inline uint16_t AttrGetPayloadLen(const nlattr* attr)
{
    return attr->nla_len - align_length(sizeof(nlattr));
}

inline void* AttrGetPayload(const nlattr* attr)
{
    return (uint8_t*)attr + align_length(sizeof(nlattr));
}

inline uint32_t AttrGetUint32(const nlattr* attr)
{
    return *((uint32_t*)AttrGetPayload(attr));
}

inline bool AttrIsOk(const nlattr* attr, int len)
{
    return len >= (int)sizeof(nlattr) && attr->nla_len >= sizeof(nlattr) &&
           (int)attr->nla_len <= len;
}

inline nlattr* AttrNext(const nlattr* attr)
{
    return (nlattr*)((uint8_t*)attr + align_length(attr->nla_len));
}

static inline nlmsghdr* CreateNetfilterHeader(void* buf, int type, uint32_t queueNumber)
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
    nfg->res_id = htons(queueNumber);

    return nlh;
}

static inline void SetAttribute(nlmsghdr* nlh, uint16_t type, size_t len, const void* data)
{
    nlattr* attr = (nlattr*)MessageGetPayloadTail(nlh);
    uint16_t payload_len = align_length(sizeof(nlattr)) + len;
    int pad;

    attr->nla_type = type;
    attr->nla_len = payload_len;

    memcpy((uint8_t*)attr + align_length(sizeof(nlattr)), data, len);
    pad = align_length(len) - len;
    if (pad > 0)
        memset((uint8_t*)attr + align_length(sizeof(nlattr)) + len, 0, pad);

    nlh->nlmsg_len += align_length(payload_len);
}

static inline nlmsghdr* SetCfgCommand(uint8_t* buf, uint16_t pf, uint8_t command, int queueNumber)
{
    nlmsghdr* nlh = CreateNetfilterHeader(buf, NFQNL_MSG_CONFIG, queueNumber);
    nfqnl_msg_config_cmd cmd;
    cmd.command = command;
    cmd.pf = htons(pf);

    SetAttribute(nlh, NFQA_CFG_CMD, sizeof(cmd), &cmd);
    return nlh;
}

static inline nlmsghdr* SetCfgParams(uint8_t* buf, uint8_t mode, int range, int queueNumber)
{
    nlmsghdr* nlh = CreateNetfilterHeader(buf, NFQNL_MSG_CONFIG, queueNumber);
    nfqnl_msg_config_params params;
    params.copy_range = htonl(range);
    params.copy_mode = mode;

    SetAttribute(nlh, NFQA_CFG_PARAMS, sizeof(params), &params);
    return nlh;
}

static inline nlmsghdr* SetVerdict(uint8_t* buf, unsigned int id, unsigned int queueNumber,
                                   int verdict, uint32_t packetLength, uint8_t* packet)
{
    nlmsghdr* nlh = CreateNetfilterHeader(buf, NFQNL_MSG_VERDICT, queueNumber);
    nfqnl_msg_verdict_hdr verdictHeader;
    verdictHeader.verdict = htonl(verdict);
    verdictHeader.id = htonl(id);

    SetAttribute(nlh, NFQA_VERDICT_HDR, sizeof(verdictHeader), &verdictHeader);
    if (packetLength)
        SetAttribute(nlh, NFQA_PAYLOAD, packetLength, packet);

    return nlh;
}

static bool ParseAttr(const nlattr* attr, void* data)
{
    const nlattr** tb = (const nlattr**)data;
    int type = attr->nla_type & NLA_TYPE_MASK;

    if (type > NFQA_MAX)
        return true;

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
        if (AttrGetPayloadLen(attr) != sizeof(uint32_t))
        {
            return false;
        }
        break;
    case NFQA_TIMESTAMP:
        if (AttrGetPayloadLen(attr) != sizeof(nfqnl_msg_packet_timestamp))
        {
            return false;
        }
        break;
    case NFQA_HWADDR:
        if (AttrGetPayloadLen(attr) != sizeof(nfqnl_msg_packet_hw))
        {
            return false;
        }
        break;
    case NFQA_PACKET_HDR:
        if (AttrGetPayloadLen(attr) != sizeof(nfqnl_msg_packet_hdr))
        {
            return false;
        }
        break;
    case NFQA_PAYLOAD:
    case NFQA_CT:
    case NFQA_EXP:
        break;
    }
    tb[type] = attr;
    return true;
}

static inline int ParseAttrs(const nlmsghdr* nlh, unsigned int offset, void* data)
{
    int ret = 1;
    const nlattr* attr;

    for (attr = (nlattr*)MessageGetPayloadOffset(nlh, offset);
         AttrIsOk(attr, (char*)MessageGetPayloadTail(nlh) - (char*)(attr)); attr = AttrNext(attr))
    {
        if ((ret = ParseAttr(attr, data)) <= 0)
            return ret;
    }
    return ret;
}

static bool ProcessMessage(const nlmsghdr* nlh, NfqRawPacket* rawPacket)
{
    nlattr* attr[NFQA_MAX + 1] = {};

    if (rawPacket->mh)
    {
        return false;
    }

    if (!ParseAttrs(nlh, sizeof(nfgenmsg), attr))
    {
        return false;
    }

    rawPacket->mh = nlh;
    rawPacket->ph = (nfqnl_msg_packet_hdr*)AttrGetPayload(attr[NFQA_PACKET_HDR]);

    timeval tv{};
    gettimeofday(&tv, nullptr);

    size_t pktlen;
    size_t framelen = AttrGetPayloadLen(attr[NFQA_PAYLOAD]);
    if (attr[NFQA_CAP_LEN])
    {
        pktlen = ntohl(AttrGetUint32(attr[NFQA_CAP_LEN]));
    }
    else
    {
        pktlen = framelen;
    }

    rawPacket->setRawData((uint8_t*)AttrGetPayload(attr[NFQA_PAYLOAD]), pktlen, tv,
                          io::LINKTYPE_RAW, framelen);

    return true;
}

int ProcessMessages(const void* buffer, size_t numbytes, unsigned int portid,
                    NfqRawPacket* rawPacket, std::error_code& ec)
{
    const nlmsghdr* nlh = static_cast<const nlmsghdr*>(buffer);
    int len = numbytes;

    while (MessageIsOk(nlh, len))
    {
        auto v = nlh->nlmsg_pid && portid ? nlh->nlmsg_pid == portid : true;
        if (!v)
        {
            ec = std::make_error_code(std::errc::no_such_process);
            return -1;
        }

        if (nlh->nlmsg_flags & NLM_F_DUMP_INTR)
        {
            ec = std::make_error_code(std::errc::interrupted);
            return -1;
        }

        if (nlh->nlmsg_type >= NLMSG_MIN_TYPE)
        {
            if (!ProcessMessage(nlh, rawPacket))
            {
                return -1;
            }
        }
        else if (nlh->nlmsg_type == NLMSG_ERROR)
        {
            const nlmsgerr* err = (nlmsgerr*)MessageGetPayload(nlh);

            if (nlh->nlmsg_len < sizeof(nlmsgerr) + align_length(sizeof(nlmsghdr)))
            {
                ec = std::make_error_code(std::errc::bad_message);
                return -1;
            }

            ec = std::make_error_code(static_cast<std::errc>(abs(err->error)));
            return ec ? 0 : -1;
        }
        else
        {
            break;
        }
        nlh = MessageNext(nlh, &len);
    }

    return 0;
}

struct NfQueue::Impl
{
    Impl();
    ~Impl() noexcept;

    ssize_t sendSocket(const void* buf, size_t len, std::error_code& ec) noexcept
    {
        sockaddr_nl snl{};
        snl.nl_family = AF_NETLINK;
        ssize_t ret;

        ret = ::sendto(socket, buf, len, 0, (sockaddr*)&snl, sizeof(snl));
        if (ret == -1)
        {
            ec = GetLastSystemError();
        }
        return ret;
    }

    ssize_t recvSocket(void* buffer, size_t bufferSize, bool blocking, std::error_code& ec) noexcept
    {
        ec.clear();

        sockaddr_nl address;
        ssize_t ret;

        iovec iov = {
            .iov_base = buffer,
            .iov_len = bufferSize,
        };
        msghdr msg = {
            .msg_name = &address,
            .msg_namelen = sizeof(address),
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = nullptr,
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

    io::PacketPool<NfqRawPacket> pool;
    uint8_t* buffer;
    size_t buffersize;
    socket::SocketType socket;
    sockaddr_nl address;
    unsigned int queueNumber;
    unsigned int queueMaxLength;
    unsigned int portid;
    int snaplen;
    int timeout;
    bool failOpen;
    volatile bool interrupted;
};

NfQueue::Impl::~Impl()
{
    closeSocket();
    delete[] buffer;
}

NfQueue::Impl::Impl()
    : queueNumber(0)
    , queueMaxLength(0)
    , portid(0)
    , snaplen(0)
    , timeout(0)
{
}

NfQueue::NfQueue(const io::DriverConfig& config)
    : impl_(std::make_unique<NfQueue::Impl>())
{
    for (const auto& [name, value] : config.getParameters())
    {
        if (iequals(name, "failOpen"))
            impl_->failOpen = false;
        else if (iequals(name, "queueMaxLength"))
            to_number(value, impl_->queueMaxLength);
    }
}

Status NfQueue::configure(const io::Config& config)
{
    std::error_code ec;

    impl_->snaplen = config.getSnaplen();
    impl_->timeout = config.getTimeout();
    impl_->queueMaxLength = ::kDefaultQueueMaxLength;

    to_number(config.getInput(), impl_->queueNumber, ec);

    impl_->buffersize = impl_->snaplen + 4096;
    impl_->buffer = new uint8_t[impl_->buffersize];

    impl_->pool.allocatePool(::kDefaultPoolSize);
    impl_->socket = socket::CreateSocket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER, ec);

    impl_->timeout = config.getTimeout();
    if (impl_->timeout)
    {
        timeval tv;
        tv.tv_sec = impl_->timeout / 1000;
        tv.tv_usec = (impl_->timeout % 1000) * 1000;
        setsockopt(impl_->socket, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv));
    }

    unsigned int socket_rcvbuf_size = impl_->queueMaxLength * impl_->snaplen;
    if (setsockopt(impl_->socket, SOL_SOCKET, SO_RCVBUFFORCE, &socket_rcvbuf_size,
                   sizeof(socket_rcvbuf_size)) == -1)
    {
        setsockopt(impl_->socket, SOL_SOCKET, SO_RCVBUF, &socket_rcvbuf_size,
                   sizeof(socket_rcvbuf_size));
    }

    impl_->bindAddress(0, 0, ec);

    nlmsghdr* nlh;

    nlh = SetCfgCommand(impl_->buffer, AF_INET, NFQNL_CFG_CMD_PF_UNBIND, 0);
    impl_->sendSocket(nlh, nlh->nlmsg_len, ec);

    nlh = SetCfgCommand(impl_->buffer, AF_INET6, NFQNL_CFG_CMD_PF_UNBIND, 0);
    impl_->sendSocket(nlh, nlh->nlmsg_len, ec);

    nlh = SetCfgCommand(impl_->buffer, AF_INET, NFQNL_CFG_CMD_PF_BIND, 0);
    impl_->sendSocket(nlh, nlh->nlmsg_len, ec);

    nlh = SetCfgCommand(impl_->buffer, AF_INET6, NFQNL_CFG_CMD_PF_BIND, 0);
    impl_->sendSocket(nlh, nlh->nlmsg_len, ec);

    nlh = SetCfgCommand(impl_->buffer, AF_UNSPEC, NFQNL_CFG_CMD_BIND, impl_->queueNumber);
    impl_->sendSocket(nlh, nlh->nlmsg_len, ec);

    nlh = SetCfgParams(impl_->buffer, NFQNL_COPY_PACKET, impl_->snaplen, impl_->queueNumber);

    uint32_t value = htonl(impl_->queueMaxLength);
    SetAttribute(nlh, NFQA_CFG_QUEUE_MAXLEN, sizeof(value), &value);

    value = htonl(NFQA_CFG_F_GSO);
    SetAttribute(nlh, NFQA_CFG_FLAGS, sizeof(value), &value);
    SetAttribute(nlh, NFQA_CFG_MASK, sizeof(value), &value);

    if (impl_->failOpen)
    {
        value = htonl(NFQA_CFG_F_FAIL_OPEN);
        SetAttribute(nlh, NFQA_CFG_FLAGS, sizeof(value), &value);
        SetAttribute(nlh, NFQA_CFG_MASK, sizeof(value), &value);
    }

    impl_->sendSocket(nlh, nlh->nlmsg_len, ec);
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
    nlmsghdr* nlh;
    std::error_code ec;

    nlh = SetCfgCommand(impl_->buffer, AF_INET, NFQNL_CFG_CMD_UNBIND, impl_->queueNumber);
    if (impl_->sendSocket(nlh, nlh->nlmsg_len, ec) == -1)
    {
        return Status::Error;
    }

    impl_->closeSocket();
    return Status::Success;
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

    NfqRawPacket* rawPacket = impl_->pool.acquirePacket();
    if (!rawPacket)
    {
        return RecvStatus::Error;
    }

    if (!rawPacket->buffer)
        rawPacket->buffer = new uint8_t[impl_->buffersize];

    ssize_t ret;
    do
    {
        ret = impl_->recvSocket(rawPacket->buffer, impl_->buffersize, true, ec);
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

        ret = ProcessMessages(rawPacket->buffer, ret, impl_->portid, rawPacket, ec);
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
    std::error_code ec;
    uint32_t plen = (verdict == Verdict::Replace) ? rawPacket->getRawDataLen() : 0;
    int nfq_verdict =
        (verdict == Verdict::Pass || verdict == Verdict::Replace) ? NF_ACCEPT : NF_DROP;

    auto nlPacket = dynamic_cast<NfqRawPacket*>(rawPacket);

    nlmsghdr* nlh = SetVerdict(impl_->buffer, ntohl(nlPacket->ph->packet_id), impl_->queueNumber,
                               nfq_verdict, plen, const_cast<uint8_t*>(rawPacket->getRawData()));

    if (impl_->sendSocket(nlh, nlh->nlmsg_len, ec) == -1)
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
