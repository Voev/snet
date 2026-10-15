#pragma once

#include <cstdint>
#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <linux/if_packet.h>
#include <linux/if_ether.h>

namespace snet::driver
{

/// @brief Default RX/TX ring buffer size in MiB.
constexpr uint32_t kDefaultBufferMb = 128;

/// @brief Maximum number of network interfaces supported by the driver.
constexpr size_t kMaxInterfaces = 32;

/// @brief Default ring allocation order (log2 of page count).
constexpr int kDefaultOrder = 5;

/// @brief Byte offset of the VLAN tag within an Ethernet frame.
constexpr int kVlanOffset = 2 * ETH_ALEN;

/// @brief Size of a VLAN tag in bytes.
constexpr size_t kVlanTagLen = 4;

/// @brief IEEE 802.1Q VLAN tag.
struct VlanTag
{
    uint16_t tpid; ///< Tag Protocol Identifier.
    uint16_t tci;  ///< Tag Control Information.
};

/// @brief Single slot in the mmap ring buffer.
struct RingEntry
{
    uint8_t* raw{nullptr};        ///< Pointer to the frame buffer for this slot.
    RingEntry* next{nullptr};     ///< Next entry in the free list, or nullptr if last.
};

/// @brief Userspace ring buffer state for a single RX or TX ring.
struct Ring
{
    tpacket_req layout{};         ///< Kernel TPACKET ring layout request.
    uint32_t size{0};             ///< Ring size in bytes.
    void* start{nullptr};         ///< Base address of the mmap'd ring.
    RingEntry* entries{nullptr};  ///< Array of ring entries.
    RingEntry* cursor{nullptr};   ///< Current position in the entry list.
};

#if defined(TPACKET_ALIGN)
/// @brief Aligns a value to the TPACKET boundary.
#define SNET_TPACKET_ALIGN(x) TPACKET_ALIGN(x)
#else
/// @brief Aligns an unsigned value up to a power-of-two boundary.
/// @param[in] x Value to align.
/// @param[in] a Alignment (must be a power of two).
/// @return Aligned value.
inline constexpr unsigned alignTo(unsigned x, unsigned a)
{
    return (x + a - 1) & ~(a - 1);
}
/// @brief Fallback TPACKET alignment macro using 16-byte alignment.
#define SNET_TPACKET_ALIGN(x) alignTo((x), 16)
#endif

} // namespace snet::driver