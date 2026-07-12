#pragma once
#include <cstdint>
#include <cstddef>

#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>

namespace snet::driver
{

inline constexpr size_t AlignLength(size_t len, size_t alignment = 4) noexcept
{
    return (len + alignment - 1) & ~(alignment - 1);
}

inline bool MessageIsOk(const nlmsghdr* nlh, int len)
{
    return len >= (int)sizeof(nlmsghdr) && nlh->nlmsg_len >= sizeof(nlmsghdr) && (int)nlh->nlmsg_len <= len;
}

inline nlmsghdr* MessageNext(const nlmsghdr* nlh, int* len)
{
    *len -= AlignLength(nlh->nlmsg_len);
    return (nlmsghdr*)((uint8_t*)nlh + AlignLength(nlh->nlmsg_len));
}

inline void* MessageGetPayload(const nlmsghdr* nlh)
{
    return (uint8_t*)nlh + AlignLength(sizeof(nlmsghdr));
}

inline void* MessageGetPayloadOffset(const nlmsghdr* nlh, size_t offset)
{
    return (uint8_t*)nlh + AlignLength(sizeof(nlmsghdr)) + AlignLength(offset);
}

inline void* MessageGetPayloadTail(const nlmsghdr* nlh)
{
    return (uint8_t*)nlh + AlignLength(nlh->nlmsg_len);
}

inline uint16_t AttrGetPayloadLen(const nlattr* attr)
{
    return attr->nla_len - AlignLength(sizeof(nlattr));
}

inline void* AttrGetPayload(const nlattr* attr)
{
    return (uint8_t*)attr + AlignLength(sizeof(nlattr));
}

inline uint32_t AttrGetUint32(const nlattr* attr)
{
    return *((uint32_t*)AttrGetPayload(attr));
}

inline bool AttrIsOk(const nlattr* attr, int len)
{
    return len >= (int)sizeof(nlattr) && attr->nla_len >= sizeof(nlattr) && (int)attr->nla_len <= len;
}

inline nlattr* AttrNext(const nlattr* attr)
{
    return (nlattr*)((uint8_t*)attr + AlignLength(attr->nla_len));
}

} // namespace snet::driver