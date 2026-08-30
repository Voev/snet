

#include <system_error>

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include <snet/socket.hpp>

#include <casket/utils/endianness.hpp>
#include <casket/utils/string.hpp>
#include <casket/utils/error_code.hpp>
#include <casket/utils/to_number.hpp>

#include <casket/log/async_logger.hpp>

#include "nl_messages.hpp"
#include "nfq_driver.hpp"

using namespace casket;
using namespace snet::socket;
using namespace snet::layers;

static constexpr std::size_t kDefaultPoolSize{16};
static constexpr std::size_t kDefaultQueueMaxLength{16};

namespace snet::driver
{

static inline nlmsghdr* CreateNetfilterHeader(void* buf, int type, uint32_t queueNumber)
{
    auto len = AlignLength(sizeof(nlmsghdr));
    nlmsghdr* nlh = static_cast<nlmsghdr*>(buf);
    std::memset(buf, 0, len);

    nlh->nlmsg_len = len;
    nlh->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | type;
    nlh->nlmsg_flags = NLM_F_REQUEST;

    len = AlignLength(sizeof(nfgenmsg));
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
    uint16_t payload_len = AlignLength(sizeof(nlattr)) + len;
    int pad;

    attr->nla_type = type;
    attr->nla_len = payload_len;

    memcpy((uint8_t*)attr + AlignLength(sizeof(nlattr)), data, len);
    pad = AlignLength(len) - len;
    if (pad > 0)
        memset((uint8_t*)attr + AlignLength(sizeof(nlattr)) + len, 0, pad);

    nlh->nlmsg_len += AlignLength(payload_len);
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

static inline nlmsghdr* SetVerdict(uint8_t* buf, unsigned int id, unsigned int queueNumber, int verdict,
                                   uint32_t packetLength, uint8_t* packet)
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

int ProcessMessages(const void* buffer, size_t numbytes, unsigned int portid, NfqPacket* nfqPacket, std::error_code& ec)
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
            if (!nfqPacket->setFromMessage(nlh))
            {
                return -1;
            }
        }
        else if (nlh->nlmsg_type == NLMSG_ERROR)
        {
            const nlmsgerr* err = (nlmsgerr*)MessageGetPayload(nlh);

            if (nlh->nlmsg_len < sizeof(nlmsgerr) + AlignLength(sizeof(nlmsghdr)))
            {
                ec = std::make_error_code(std::errc::bad_message);
                return -1;
            }

            ec = std::make_error_code(static_cast<std::errc>(abs(err->error)));
            return err->error == 0 ? 0 : -1;
        }
        else
        {
            break;
        }
        nlh = MessageNext(nlh, &len);
    }

    return 0;
}

NfQueue::NfQueue(const io::DriverConfig& config)
    : buffer_(nullptr)
    , bufferSize_(0)
    , queueNumber_(0)
    , queueMaxLength_(::kDefaultQueueMaxLength)
    , portid_(0)
    , snaplen_(0)
    , timeout_(0)
    , failOpen_(true)
    , interrupted_(false)
{
    (void)config;
}

NfQueue::~NfQueue()
{
    closeSocket();
    delete[] buffer_;
}

Status NfQueue::configure(const io::Config& config)
{
    std::error_code ec;

    snaplen_ = config.getSnaplen();
    timeout_ = config.getTimeout();

    for (const auto& [name, value] : config.getParameters())
    {
        if (iequals(name, "fail_open"))
        {
            failOpen_ = false;
        }
        else if (iequals(name, "queue_max_length"))
        {
            to_number(value, queueMaxLength_);
        }
    }

    to_number(config.getInput(), queueNumber_, ec);

    bufferSize_ = snaplen_ + 4096;
    buffer_ = new uint8_t[bufferSize_];

    pool_ = std::make_unique<casket::FixedObjectPool<NfqPacket>>(config.getMsgPoolSize(), bufferSize_);
    socket_ = socket::CreateSocket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER, ec);

    timeout_ = config.getTimeout();
    if (timeout_)
    {
        timeval tv;
        tv.tv_sec = timeout_ / 1000;
        tv.tv_usec = (timeout_ % 1000) * 1000;
        setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv));
    }

    unsigned int socketRcvBufSize = queueMaxLength_ * snaplen_;
    if (setsockopt(socket_, SOL_SOCKET, SO_RCVBUFFORCE, &socketRcvBufSize, sizeof(socketRcvBufSize)) == -1)
    {
        setsockopt(socket_, SOL_SOCKET, SO_RCVBUF, &socketRcvBufSize, sizeof(socketRcvBufSize));
    }

    bindAddress(0, 0, ec);

    nlmsghdr* nlh;

    nlh = SetCfgCommand(buffer_, AF_INET, NFQNL_CFG_CMD_PF_UNBIND, 0);
    sendSocket(nlh, nlh->nlmsg_len, ec);

    nlh = SetCfgCommand(buffer_, AF_INET6, NFQNL_CFG_CMD_PF_UNBIND, 0);
    sendSocket(nlh, nlh->nlmsg_len, ec);

    nlh = SetCfgCommand(buffer_, AF_INET, NFQNL_CFG_CMD_PF_BIND, 0);
    sendSocket(nlh, nlh->nlmsg_len, ec);

    nlh = SetCfgCommand(buffer_, AF_INET6, NFQNL_CFG_CMD_PF_BIND, 0);
    sendSocket(nlh, nlh->nlmsg_len, ec);

    nlh = SetCfgCommand(buffer_, AF_UNSPEC, NFQNL_CFG_CMD_BIND, queueNumber_);
    sendSocket(nlh, nlh->nlmsg_len, ec);

    nlh = SetCfgParams(buffer_, NFQNL_COPY_PACKET, snaplen_, queueNumber_);

    uint32_t value = htonl(queueMaxLength_);
    SetAttribute(nlh, NFQA_CFG_QUEUE_MAXLEN, sizeof(value), &value);

    value = htonl(NFQA_CFG_F_GSO);
    if (failOpen_)
    {
        value |= htonl(NFQA_CFG_F_FAIL_OPEN);
    }

    SetAttribute(nlh, NFQA_CFG_FLAGS, sizeof(value), &value);
    SetAttribute(nlh, NFQA_CFG_MASK, sizeof(value), &value);

    sendSocket(nlh, nlh->nlmsg_len, ec);
    return Status::Success;
}

std::shared_ptr<io::Driver> NfQueue::create(const io::DriverConfig& config)
{
    return std::make_shared<NfQueue>(config);
}

Status NfQueue::start()
{
    return Status::Success;
}

Status NfQueue::interrupt()
{
    interrupted_ = true;
    return Status::Success;
}

Status NfQueue::stop()
{
    nlmsghdr* nlh;
    std::error_code ec;

    nlh = SetCfgCommand(buffer_, AF_INET, NFQNL_CFG_CMD_UNBIND, queueNumber_);
    if (sendSocket(nlh, nlh->nlmsg_len, ec) == -1)
    {
        CSK_LOG_ERROR("error sending data over socket: %s", ec.message().c_str());
        return Status::Error;
    }

    closeSocket();
    return Status::Success;
}

layers::LinkLayerType NfQueue::getDataLinkType() const
{
    return layers::LINKTYPE_RAW;
}

RecvStatus NfQueue::receivePackets(layers::Packet** packets, uint16_t* packetCount, uint16_t maxCount)
{
    RecvStatus rstat{RecvStatus::Ok};
    std::error_code ec;
    NfqPacket* nfqPacket{nullptr};
    uint16_t i{};
    ssize_t ret{};

    for (i = 0; i < maxCount; ++i)
    {
        if (interrupted_)
        {
            interrupted_ = false;
            rstat = RecvStatus::Interrupted;
            break;
        }

        nfqPacket = pool_->acquire();
        if (!nfqPacket)
        {
            CSK_LOG_ERROR("error taking packet from pool");
            rstat = RecvStatus::Error;
            break;
        }

        ret = recvSocket(nfqPacket->getData(), nfqPacket->getCapacity(), true, ec);
        if (ret < 0)
        {
            if (ec == std::errc::no_buffer_space)
            {
                stats_.hw_packets_dropped++;
                continue;
            }
            else if (ec == std::errc::resource_unavailable_try_again || ec == std::errc::operation_would_block)
            {
                rstat = RecvStatus::Interrupted;
            }
            else if (ec == std::errc::interrupted)
            {
                if (!interrupted_)
                {
                    continue;
                }
                interrupted_ = false;
                rstat = RecvStatus::Interrupted;
            }
            else
            {
                CSK_LOG_ERROR("error receiving data from socket: %s", ec.message().c_str());
                rstat = RecvStatus::Error;
            }
            break;
        }

        ret = ProcessMessages(nfqPacket->getData(), ret, portid_, nfqPacket, ec);
        if (ret < 0)
        {
            CSK_LOG_ERROR("error processing data from socket: %s", ec.message().c_str());
            rstat = RecvStatus::Error;
            break;
        }

        packets[i] = nfqPacket->asPacket();
    }

    if (packetCount)
    {
        *packetCount = i;
    }

    return rstat;
}

Status NfQueue::finalizePacket(layers::Packet* packet, Verdict verdict)
{
    std::error_code ec;
    uint32_t plen = (verdict == Verdict::Replace) ? packet->getDataLen() : 0;
    int nfqVerdict = (verdict == Verdict::Pass || verdict == Verdict::Replace) ? NF_ACCEPT : NF_DROP;

    auto nfqPacket = NfqPacket::fromPacket(packet);

    nlmsghdr* nlh = SetVerdict(
        buffer_, nfqPacket->getPacketId(), queueNumber_, nfqVerdict, plen, const_cast<uint8_t*>(packet->getData()));

    if (sendSocket(nlh, nlh->nlmsg_len, ec) == -1)
    {
        return Status::Error;
    }

    pool_->release(nfqPacket);

    return Status::Success;
}

Status NfQueue::inject(const uint8_t* data, uint32_t dataLength)
{
    (void)data;
    (void)dataLength;
    return Status::NotSupported;
}

const char* NfQueue::getName() const
{
    return "nf_queue";
}

Status NfQueue::getStats(Stats* stats)
{
    stats_.hw_packets_received = stats_.packets_received;
    memcpy(stats, &stats_, sizeof(Stats));
    return Status::Success;
}

void NfQueue::resetStats()
{
    memset(&stats_, 0, sizeof(Stats));
}

int NfQueue::getSnaplen() const
{
    return snaplen_;
}

Status NfQueue::getMsgPoolInfo(io::PacketPoolInfo& info)
{
    auto capacity = pool_->capacity();

    info.size = capacity;
    /// @todo: fix it.
    info.available = 0;
    info.memorySize = sizeof(NfqPacket) * capacity;
    return Status::Success;
}

ssize_t NfQueue::sendSocket(const void* buf, size_t len, std::error_code& ec) noexcept
{
    sockaddr_nl snl{};
    snl.nl_family = AF_NETLINK;
    ssize_t ret;

    ret = ::sendto(socket_, buf, len, 0, (sockaddr*)&snl, sizeof(snl));
    if (ret == -1)
    {
        ec = GetLastSystemError();
    }
    return ret;
}

ssize_t NfQueue::recvSocket(void* buffer, size_t bufferSize, bool blocking, std::error_code& ec) noexcept
{
    ec.clear();

    sockaddr_nl address;
    ssize_t ret;

    iovec iov{};
    iov.iov_base = buffer;
    iov.iov_len = bufferSize;

    msghdr msg{};
    msg.msg_name = &address;
    msg.msg_namelen = sizeof(address);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = nullptr;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    ret = ::recvmsg(socket_, &msg, blocking ? 0 : MSG_DONTWAIT);
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

void NfQueue::bindAddress(unsigned int groups, pid_t pid, std::error_code& ec) noexcept
{
    address_.nl_family = AF_NETLINK;
    address_.nl_groups = groups;
    address_.nl_pid = pid;

    int ret = ::bind(socket_, reinterpret_cast<sockaddr*>(&address_), sizeof(address_));
    if (ret < 0)
    {
        ec = GetLastSystemError();
        return;
    }

    socklen_t addressLength = sizeof(address_);
    ret = getsockname(socket_, reinterpret_cast<sockaddr*>(&address_), &addressLength);
    if (ret < 0)
    {
        ec = GetLastSystemError();
        return;
    }

    if (addressLength != sizeof(address_) || address_.nl_family != AF_NETLINK)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
    }
}

void NfQueue::closeSocket() noexcept
{
    if (socket_ != InvalidSocket)
    {
        CloseSocket(socket_);
        socket_ = InvalidSocket;
    }
}

} // namespace snet::driver

SNET_DLL_ALIAS(snet::driver::NfQueue::create, CreateDriver)
