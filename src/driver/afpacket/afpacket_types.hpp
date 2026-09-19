#pragma once

#include <cstdint>
#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <linux/if_packet.h>
#include <linux/if_ether.h>

namespace snet::driver
{

constexpr uint32_t kDefaultBufferMb = 128;
constexpr size_t kMaxInterfaces = 32;
constexpr int kDefaultOrder = 5;
constexpr int kVlanOffset = 2 * ETH_ALEN;
constexpr size_t kVlanTagLen = 4;

struct VlanTag
{
    uint16_t tpid;
    uint16_t tci;
};


#if defined(TPACKET_ALIGN)
#define SNET_TPACKET_ALIGN(x) TPACKET_ALIGN(x)
#else
inline constexpr unsigned alignTo(unsigned x, unsigned a)
{
    return (x + a - 1) & ~(a - 1);
}
#define SNET_TPACKET_ALIGN(x) alignTo((x), 16)
#endif

} // namespace snet::driver