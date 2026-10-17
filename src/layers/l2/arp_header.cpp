#include <snet/layers/l2/arp_header.hpp>
#include <snet/layers/l2/mac_address.hpp>
#include <snet/layers/l3/ipv4_address.hpp>
#include <snet/layers/packet.hpp>

#include <arpa/inet.h>
#include <cstdio>

namespace snet::layers
{

bool ArpHeader::initialize(const LayerInfo& layer, const Packet& packet) noexcept
{
    if (layer.headerLength < sizeof(arp_header))
    {
        header_ = nullptr;
        return false;
    }

    if (packet.getDataLen() < layer.offset + sizeof(arp_header))
    {
        header_ = nullptr;
        return false;
    }

    header_ = reinterpret_cast<const RawType*>(packet.getData() + layer.offset);
    return true;
}

namespace
{

const char* opToString(ArpOp op) noexcept
{
    switch (op)
    {
    case ArpOp::Request:
        return "Request";
    case ArpOp::Reply:
        return "Reply";
    case ArpOp::RarpRequest:
        return "RARP Request";
    case ArpOp::RarpReply:
        return "RARP Reply";
    case ArpOp::InarpRequest:
        return "InARP Request";
    case ArpOp::InarpReply:
        return "InARP Reply";
    case ArpOp::ArpNak:
        return "ARP NAK";
    default:
        return "Unknown";
    }
}

} // namespace

std::ostream& ArpHeader::print(std::ostream& os) const noexcept
{
    if (!header_)
    {
        os << "ARP: <invalid>";
        return os;
    }

    // clang-format off
    os << "ARP " << opToString(operation())
       << " htype=" << hardwareType()
       << " ptype=0x" << std::hex << protocolType() << std::dec
       << " sha=" << MacAddress(senderHwAddr())
       << " spa=" << IPv4Address::fromNetwork(senderProtoAddr())
       << " tha=" << MacAddress(targetHwAddr())
       << " tpa=" << IPv4Address::fromNetwork(targetProtoAddr());
    // clang-format on

    return os;
}

} // namespace snet::layers