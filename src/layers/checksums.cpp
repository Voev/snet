#include <snet/layers/checksums.hpp>

#include <algorithm>
#include <array>
#include <utility>

#include <casket/utils/load_store.hpp>

using namespace casket;

namespace snet::layers
{
namespace
{

/// Folds a 32-bit accumulator into a 16-bit ones'-complement sum.
inline constexpr uint32_t fold(uint32_t sum) noexcept
{
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    return sum;
}

constexpr uint32_t kFnvPrime = 16777619u;
constexpr uint32_t kFnvOffset = 2166136261u;

} // namespace

uint16_t computeChecksum(ByteSpanVec vec)
{
    uint32_t sum = 0;

    for (auto buf : vec)
    {
        uint32_t localSum = 0;
        const size_t n = buf.size();
        size_t i = 0;

        // Process 16-bit big-endian words.
        for (; i + 1 < n; i += 2)
            localSum += load_be<uint16_t>(buf.data(), i / 2);

        // Odd trailing byte: treated as the high byte of a 16-bit word.
        if (i < n)
            localSum += static_cast<uint16_t>(buf[i]) << 8;

        sum += fold(localSum);
    }

    sum = fold(sum);

    // One's complement, returned in network byte order.
    const uint16_t result = static_cast<uint16_t>(~sum);
    return host_to_be(result);
}

uint16_t computePseudoHdrChecksum(ByteSpan data, uint8_t ipAddrType, uint8_t protocolType,
                                  const IPAddress& srcIPAddress, const IPAddress& dstIPAddress)
{
    if (ipAddrType == 4)
    {
        const uint32_t srcIP = srcIPAddress.toIPv4().toHost();
        const uint32_t dstIP = dstIPAddress.toIPv4().toHost();
        const uint16_t len = static_cast<uint16_t>(data.size());

        // IPv4 pseudo header (RFC 793):
        //   +--------+--------+--------+--------+
        //   |           Source Address          |
        //   +--------+--------+--------+--------+
        //   |         Destination Address       |
        //   +--------+--------+--------+--------+
        //   |  zero  |  Proto |    TCP Length   |
        //   +--------+--------+--------+--------+
        std::array<uint8_t, 12> ph{};
        store_be<uint32_t>(srcIP, ph.data(), 0);
        store_be<uint32_t>(dstIP, ph.data(), 1);
        ph[8] = 0;
        ph[9] = protocolType;
        store_be<uint16_t>(len, ph.data(), 5);

        const std::array<ByteSpan, 2> vec{ByteSpan{ph}, data};
        return computeChecksum(vec);
    }

    if (ipAddrType == 6)
    {
        const uint32_t len = static_cast<uint32_t>(data.size());

        // IPv6 pseudo header (RFC 8200 §8.1):
        //   +--------+--------+--------+--------+
        //   |          Source Address (16)      |
        //   +--------+--------+--------+--------+
        //   |       Destination Address (16)    |
        //   +--------+--------+--------+--------+
        //   |        Upper-Layer Length (32)    |
        //   +--------+--------+--------+--------+
        //   |  zero  |  zero  |  zero  | NextHdr|
        //   +--------+--------+--------+--------+
        std::array<uint8_t, 40> ph{};

        const auto srcIP = srcIPAddress.toIPv6();
        const auto dstIP = dstIPAddress.toIPv6();

        std::copy(srcIP.begin(), srcIP.end(), ph.begin());
        std::copy(dstIP.begin(), dstIP.end(), ph.begin() + 16);

        store_be<uint32_t>(len, ph.data(), 8); // 32..35

        ph[36] = 0;
        ph[37] = 0;
        ph[38] = 0;
        ph[39] = protocolType;

        const std::array<ByteSpan, 2> vec{ByteSpan{ph}, data};
        return computeChecksum(vec);
    }

    return 0;
}

uint32_t fnvHash(ByteSpanVec vec)
{
    uint32_t hash = kFnvOffset;
    for (auto buf : vec)
    {
        for (uint8_t b : buf)
        {
            hash ^= b;
            hash *= kFnvPrime;
        }
    }
    return hash;
}

uint32_t fnvHash(ByteSpan buffer)
{
    const ByteSpan one[1] = {buffer};
    return fnvHash(ByteSpanVec{one, 1});
}

uint32_t hash5Tuple(const IPAddress& addrSrc, const IPAddress& addrDst, uint16_t portSrc, uint16_t portDst,
                    uint8_t protocol, bool directionUnique)
{
    const IPAddress* pSrcAddr = &addrSrc;
    const IPAddress* pDstAddr = &addrDst;
    uint16_t pSrcPort = portSrc;
    uint16_t pDstPort = portDst;

    // For direction-agnostic hashing, order endpoints consistently.
    if (!directionUnique)
    {
        const bool swap = (*pDstAddr < *pSrcAddr) || (!(*pSrcAddr < *pDstAddr) && pDstPort < pSrcPort);
        if (swap)
        {
            std::swap(pSrcAddr, pDstAddr);
            std::swap(pSrcPort, pDstPort);
        }
    }

    // Serialize ports in a fixed byte order so that the hash is
    // platform-independent.
    std::array<uint8_t, 2> portSrcBe{};
    std::array<uint8_t, 2> portDstBe{};
    store_be<uint16_t>(pSrcPort, portSrcBe.data(), 0);
    store_be<uint16_t>(pDstPort, portDstBe.data(), 0);

    const ByteSpan srcBytes{pSrcAddr->asData(), pSrcAddr->size()};
    const ByteSpan dstBytes{pDstAddr->asData(), pDstAddr->size()};

    const std::array<ByteSpan, 5> vec{
        ByteSpan{portSrcBe},
        ByteSpan{portDstBe},
        srcBytes,
        dstBytes,
        ByteSpan{&protocol, 1},
    };

    return fnvHash(vec);
}

} // namespace snet::layers