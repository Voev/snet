#pragma once
#include <linux/netfilter/nfnetlink_queue.h>

namespace snet::netlink
{

/// @brief Header of a Netlink message.
using MessageHeader = struct nlmsghdr;

using NfMessageHeader = struct nfgenmsg;

/// @brief Netlink message packet header when working with NFQUEUE.
using MessagePacketHeader = struct nfqnl_msg_packet_hdr;

/// @brief Netlink attribute.
using NlAttribute = struct nlattr;

using SocketAddress = struct sockaddr_nl;

} // namespace snet::netlink

int mnl_cb_run_my(const void* buf, size_t numbytes, unsigned int seq, unsigned int portid,
                  mnl_cb_t cb_data, void* data);