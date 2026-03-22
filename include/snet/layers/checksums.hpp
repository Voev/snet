#pragma once

#include <snet/layers/packet.hpp>
#include <snet/layers/l3/ip_address.hpp>

namespace snet::layers
{
/**
 * A struct that represent a single buffer
 */
template <typename T>
struct ScalarBuffer
{
    /**
     * The pointer to the buffer
     */
    T* buffer;

    /**
     * Buffer length
     */
    size_t len;
};

/**
 * Computes the checksum for a vector of buffers
 * @param[in] vec The vector of buffers
 * @param[in] vecSize Number of ScalarBuffers in vector
 * @return The checksum result
 */
uint16_t computeChecksum(ScalarBuffer<uint16_t> vec[], size_t vecSize);

/**
 * Computes the checksum for Pseudo header
 * @param[in] dataPtr Data pointer
 * @param[in] dataLen Data length
 * @param[in] ipAddrType IP address type(IPv4/IPv6) type @ref
 * IPAddress::AddressType
 * @param[in] protocolType Current protocol type @ref IPProtocolTypes
 * @param[in] srcIPAddress Source IP Address
 * @param[in] dstIPAddress Destination IP Address
 * @return The checksum result
 */
uint16_t computePseudoHdrChecksum(uint8_t* dataPtr, size_t dataLen,
                                  IPAddress::Type ipAddrType,
                                  uint8_t protocolType, IPAddress srcIPAddress,
                                  IPAddress dstIPAddress);

/**
 * Computes Fowler-Noll-Vo (FNV-1) 32bit hash function on an array of byte
 * buffers. The hash is calculated on each byte in each byte buffer, as if all
 * byte buffers were one long byte buffer
 * @param[in] vec An array of byte buffers (ScalarBuffer of type uint8_t)
 * @param[in] vecSize The length of vec
 * @return The 32bit hash value
 */
uint32_t fnvHash(ScalarBuffer<uint8_t> vec[], size_t vecSize);

/**
 * Computes Fowler-Noll-Vo (FNV-1) 32bit hash function on a byte buffer
 * @param[in] buffer The byte buffer
 * @param[in] bufSize The size of the byte buffer
 * @return The 32bit hash value
 */
uint32_t fnvHash(uint8_t* buffer, size_t bufSize);

/// @brief Computes a hash value from a 5-tuple network flow identifier.
/// 
/// Generates a hash based on the standard 5-tuple (source IP, destination IP,
/// source port, destination port, protocol) used to uniquely identify network flows.
/// The hash can optionally be made direction-agnostic by sorting the source and
/// destination addresses and ports.
/// 
/// @param [in] addrSrc Source IP address.
/// @param [in] addrDst Destination IP address.
/// @param [in] portSrc Source port number.
/// @param [in] portDst Destination port number.
/// @param [in] protocol IP protocol number (e.g., TCP=6, UDP=17).
/// @param [in] directionUnique When true, hash is direction-independent by swapping
///                              source and destination fields to ensure the same
///                              hash for both directions of a flow.
///
/// @return Hash value computed from the 5-tuple.
uint32_t hash5Tuple(const IPAddress& addrSrc, const IPAddress& addrDst, uint16_t portSrc, uint16_t portDst,
                    uint8_t protocol, bool const& directionUnique = false);

} // namespace snet::layers
