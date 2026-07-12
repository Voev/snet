#include <snet/layers/timestamp.hpp>

#include "nl_messages.hpp"
#include "nfq_packet.hpp"

namespace snet::driver
{

static bool ParseAttr(const nlattr* attr, void* data)
{
    const nlattr** tb = (const nlattr**)data;
    int type = attr->nla_type & NLA_TYPE_MASK;

    if (type > NFQA_MAX)
    {
        return true;
    }

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
    {
        if (AttrGetPayloadLen(attr) != sizeof(uint32_t))
        {
            return false;
        }
        break;
    }
    case NFQA_TIMESTAMP:
    {
        if (AttrGetPayloadLen(attr) != sizeof(nfqnl_msg_packet_timestamp))
        {
            return false;
        }
        break;
    }
    case NFQA_HWADDR:
    {
        if (AttrGetPayloadLen(attr) != sizeof(nfqnl_msg_packet_hw))
        {
            return false;
        }
        break;
    }
    case NFQA_PACKET_HDR:
    {
        if (AttrGetPayloadLen(attr) != sizeof(nfqnl_msg_packet_hdr))
        {
            return false;
        }
        break;
    }
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
         AttrIsOk(attr, (char*)MessageGetPayloadTail(nlh) - (char*)(attr));
         attr = AttrNext(attr))
    {
        if ((ret = ParseAttr(attr, data)) <= 0)
        {
            return ret;
        }
    }
    return ret;
}

bool NfqPacket::setFromMessage(const nlmsghdr* nlh)
{
    if (mh_)
    {
        return false;
    }

    nlattr* attr[NFQA_MAX + 1] = {};
    if (!ParseAttrs(nlh, sizeof(nfgenmsg), attr))
    {
        return false;
    }

    mh_ = nlh;
    ph_ = (nfqnl_msg_packet_hdr*)AttrGetPayload(attr[NFQA_PACKET_HDR]);

    size_t framelen = AttrGetPayloadLen(attr[NFQA_PAYLOAD]);
    size_t pktlen = framelen;

    if (attr[NFQA_CAP_LEN])
    {
        pktlen = casket::be_to_host(AttrGetUint32(attr[NFQA_CAP_LEN]));
    }

    packet_.setRawData({(uint8_t*)AttrGetPayload(attr[NFQA_PAYLOAD]), pktlen}, layers::LINKTYPE_RAW);
    packet_.setTimestamp(layers::Timestamp::currentTime());
    return true;
}

} // namespace snet::driver