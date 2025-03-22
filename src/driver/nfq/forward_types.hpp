#pragma once
#include <linux/netfilter/nfnetlink_queue.h>

/// @brief Header of a Netlink message.
using NlMessageHeader = struct nlmsghdr;

/// @brief Netlink message packet header when working with NFQUEUE.
using NlMessagePacketHeader = struct nfqnl_msg_packet_hdr;

/// @brief Netlink attribute.
using NlAttribute = struct nlattr;
