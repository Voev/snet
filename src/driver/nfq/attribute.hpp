#pragma once
#include <snet/layers/tlv.hpp>

enum NfAttrEnumType
{
    Unpec = 0,
    PacketHeader,
    VerdictHeader,
    Mark,
    Timestamp, /* nfqnl_msg_packet_timestamp */
    IfIndex_InDev,         /* __u32 ifindex */
    IfIndex_OutDev,        /* __u32 ifindex */
    IFINDEX_PHYSINDEV,     /* __u32 ifindex */
    IFINDEX_PHYSOUTDEV,    /* __u32 ifindex */
    HwAddr,                /* nfqnl_msg_packet_hw */
    Payload,               /* opaque data payload */
    Conntrack,                    /* nfnetlink_conntrack.h */
    ConntrackInfo,               /* enum ip_conntrack_info */
    CapturedLength,               /* __u32 length of captured packet */
    SkbMetaInfo,              /* __u32 skb meta information */
    Exp,                   /* nfnetlink_conntrack.h */
    UID,                   /* __u32 sk uid */
    GID,                   /* __u32 sk gid */
    SecuirtyContext,                /* security context string */
    VLAN,                  /* nested attribute: packet vlan info */
    L2HDR,                 /* full L2 header */
    Priority,              /* skb->priority */
};

class NfqAttribute : public snet::layers::TLVRecord<uint16_t, uint16_t>
{
public:
    NfqAttribute(uint8_t* data)
        : TLVRecord(data)
    {
    }

    size_t getTotalSize() const override
    {
        return m_Data ? m_Data->recordLen : 0U;
    }

    size_t getDataSize() const override
    {
        return m_Data->recordLen;
    }

};

class NfqAttributeReader : public snet::layers::TLVRecordReader<NfqAttribute>
{
public:
    NfqAttributeReader() = default;
};