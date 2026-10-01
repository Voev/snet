#pragma once

#include <cstdint>
#include <span>
#include <array>

#include <snet/layers/l3/ip_address.hpp>

namespace snet::layers
{

/// A contiguous read-only buffer of bytes.
using ByteSpan = std::span<const uint8_t>;

/// A set of byte buffers, logically concatenated into a single byte stream.
using ByteSpanVec = std::span<const ByteSpan>;

/**
 * Computes the Internet checksum (RFC 1071) over a vector of byte buffers.
 *
 * All buffers are treated as one continuous big-endian byte stream.
 * If the total length is odd, the final byte is interpreted as the high
 * byte of a 16-bit word (low byte = 0), as required by RFC 1071 §3.
 *
 * @param[in] vec  Vector of byte buffers.
 * @return Checksum in network byte order (big-endian).
 */
uint16_t computeChecksum(ByteSpanVec vec);

/**
 * Computes the checksum for a transport-layer pseudo header (IPv4/IPv6)
 * combined with the payload.
 *
 * @param[in] data          Transport payload (TCP/UDP/etc.).
 * @param[in] ipAddrType    IP address family: 4 or 6.
 * @param[in] protocolType  IP protocol number (e.g. TCP=6, UDP=17).
 * @param[in] srcIPAddress  Source IP address.
 * @param[in] dstIPAddress  Destination IP address.
 * @return Checksum in network byte order (big-endian).
 */
uint16_t computePseudoHdrChecksum(ByteSpan data,
                                  uint8_t ipAddrType,
                                  uint8_t protocolType,
                                  const IPAddress& srcIPAddress,
                                  const IPAddress& dstIPAddress);

/**
 * Computes the Fowler-Noll-Vo (FNV-1a, 32-bit) hash over a vector of byte
 * buffers, as if they were one continuous byte stream.
 *
 * @param[in] vec  Vector of byte buffers.
 * @return 32-bit hash value.
 */
uint32_t fnvHash(ByteSpanVec vec);

/**
 * Computes the Fowler-Noll-Vo (FNV-1a, 32-bit) hash over a single byte buffer.
 *
 * @param[in] buffer  Byte buffer.
 * @return 32-bit hash value.
 */
uint32_t fnvHash(ByteSpan buffer);

/// @brief Computes a hash value from a 5-tuple network flow identifier.
///
/// Generates a hash based on the standard 5-tuple (source IP, destination IP,
/// source port, destination port, protocol) used to uniquely identify network
/// flows. When @p directionUnique is false, the hash is made
/// direction-agnostic by sorting the endpoints so that both directions of a
/// flow produce the same hash.
///
/// @param [in] addrSrc         Source IP address.
/// @param [in] addrDst         Destination IP address.
/// @param [in] portSrc         Source port number (host order).
/// @param [in] portDst         Destination port number (host order).
/// @param [in] protocol        IP protocol number (e.g. TCP=6, UDP=17).
/// @param [in] directionUnique When true, hash depends on direction of the flow.
///
/// @return Hash value computed from the 5-tuple.
uint32_t hash5Tuple(const IPAddress& addrSrc,
                    const IPAddress& addrDst,
                    uint16_t portSrc,
                    uint16_t portDst,
                    uint8_t protocol,
                    bool directionUnique = true);

} // namespace snet::layers