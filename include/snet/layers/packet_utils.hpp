#pragma once

#include <snet/layers/packet.hpp>
#include <snet/layers/l3/ip_address.hpp>
#include <snet/layers/l4/tcp_header.hpp>

namespace snet::layers
{

inline bool extractPacketInfo(Packet* packet, IPAddress& srcIP, IPAddress& dstIP, TCPHeader& hdr, const LayerInfo*& tcpLayer)
{
    auto ipHeader = packet->getHeader<IPv4Header>(IPv4);
    if (!ipHeader.isValid())
        return false;

    srcIP = IPAddress(ipHeader.srcAddr());
    dstIP = IPAddress(ipHeader.dstAddr());

    tcpLayer = packet->findLayer(TCP);
    if (!tcpLayer)
        return false;

    hdr = packet->getHeader<TCPHeader>(*tcpLayer);
    return true;
}

} // namespace snet::layers