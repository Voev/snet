#pragma once
#include <cstdint>

namespace snet::layers
{

enum IPProto : uint8_t
{
    IP = 0,
    HOPOPTS = 0,
    ICMPV4 = 1,
    IGMP = 2,
    IPIP = 4,
    TCP = 6,
    UDP = 17,
    IPV6 = 41,
    ROUTING = 43,
    FRAGMENT = 44,
    GRE = 47,
    ESP = 50,
    AUTH = 51,
    SWIPE = 53,
    MOBILITY = 55,
    ICMPV6 = 58,
    NONEXT = 59,
    DSTOPTS = 60,
    SUN_ND = 77,
    PIM = 103,
    PGM = 113,
    MOBILITY_IPV6 = 135,
    MPLS_IP = 137,
    MIN_UNASSIGNED_IP_PROTO = 143,
    RESERVED = 255,
    PORT_SCAN = 255,
    PROTO_NOT_SET = 255,
};

} // namespace snet::layers