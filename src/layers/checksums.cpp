#include <casket/utils/endianness.hpp>

#include <snet/layers/checksums.hpp>

using namespace casket;

namespace snet::layers
{

uint16_t computeChecksum(ScalarBuffer<uint16_t> vec[], size_t vecSize)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < vecSize; i++)
    {
        uint32_t localSum = 0;

        // vec len is in bytes
        for (size_t j = 0; j < vec[i].len / 2; j++)
        {
            localSum += vec[i].buffer[j];
        }

        // check if there is one byte left
        if (vec[i].len % 2)
        {
            // access to the last byte using an uint8_t pointer
            uint8_t* vecBytes = (uint8_t*)vec[i].buffer;
            uint8_t lastByte = vecBytes[vec[i].len - 1];
            // We have read the latest byte manually but this byte should be
            // properly interpreted as a 0xFF on LE and a 0xFF00 on BE to have a
            // proper checksum computation
            localSum += be_to_host<uint16_t>(lastByte << 8);
        }

        // carry count is added to the sum
        while (localSum >> 16)
        {
            localSum = (localSum & 0xffff) + (localSum >> 16);
        }
        sum += localSum;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // To obtain the checksum we take the ones' complement of this result
    uint16_t result = sum;
    result = ~result;

    // We return the result in BigEndian byte order
    return host_to_be(result);
}

uint16_t computePseudoHdrChecksum(uint8_t* dataPtr, size_t dataLen, IPAddress::Type ipAddrType, uint8_t protocolType,
                                  IPAddress srcIPAddress, IPAddress dstIPAddress)
{
    uint16_t checksumRes = 0;
    ScalarBuffer<uint16_t> vec[2];
    vec[0].buffer = (uint16_t*)dataPtr;
    vec[0].len = dataLen;

    if (ipAddrType == IPAddress::IPv4)
    {
        uint32_t srcIP = srcIPAddress.toIPv4().toUint();
        uint32_t dstIP = dstIPAddress.toIPv4().toUint();
        uint16_t pseudoHeader[6];
        pseudoHeader[0] = srcIP >> 16;
        pseudoHeader[1] = srcIP & 0xFFFF;
        pseudoHeader[2] = dstIP >> 16;
        pseudoHeader[3] = dstIP & 0xFFFF;
        pseudoHeader[4] = 0xffff & host_to_be<uint16_t>(dataLen);
        pseudoHeader[5] = host_to_be<uint16_t>(0x00ff & protocolType);
        vec[1].buffer = pseudoHeader;
        vec[1].len = 12;
        checksumRes = computeChecksum(vec, 2);
    }
    else if (ipAddrType == IPAddress::IPv6)
    {
        std::array<uint16_t, 18> pseudoHeader{};
        auto srcIP = srcIPAddress.toIPv6();
        auto dstIP = dstIPAddress.toIPv6();

        std::copy(srcIP.begin(), srcIP.end(), pseudoHeader.begin());
        std::copy(dstIP.begin(), dstIP.end(), pseudoHeader.begin() + 8);

        pseudoHeader[16] = 0xffff & host_to_be<uint16_t>(dataLen);
        pseudoHeader[17] = host_to_be<uint16_t>(0x00ff & protocolType);
        vec[1].buffer = pseudoHeader.data();
        vec[1].len = 36;
        checksumRes = computeChecksum(vec, 2);
    }

    return checksumRes;
}

static const uint32_t FNV_PRIME = 16777619u;
static const uint32_t OFFSET_BASIS = 2166136261u;

uint32_t fnvHash(ScalarBuffer<uint8_t> vec[], size_t vecSize)
{
    uint32_t hash = OFFSET_BASIS;
    for (size_t i = 0; i < vecSize; ++i)
    {
        for (size_t j = 0; j < vec[i].len; ++j)
        {
            hash *= FNV_PRIME;
            hash ^= vec[i].buffer[j];
        }
    }
    return hash;
}

uint32_t fnvHash(uint8_t* buffer, size_t bufSize)
{
    ScalarBuffer<uint8_t> scalarBuf;
    scalarBuf.buffer = buffer;
    scalarBuf.len = bufSize;
    return fnvHash(&scalarBuf, 1);
}

uint32_t hash5Tuple(const IPAddress& addrSrc, const IPAddress& addrDst, uint16_t portSrc, uint16_t portDst,
                    uint8_t protocol, bool const& directionUnique)
{
    ScalarBuffer<uint8_t> vec[5];

    int srcPosition = 0;

    if (!directionUnique)
    {
        if (portDst < portSrc)
            srcPosition = 1;
    }

    vec[0 + srcPosition].buffer = (uint8_t*)&portSrc;
    vec[0 + srcPosition].len = 2;
    vec[1 - srcPosition].buffer = (uint8_t*)&portDst;
    vec[1 - srcPosition].len = 2;

    if (!directionUnique && portSrc == portDst && addrDst < addrSrc)
        srcPosition = 1;

    vec[2 + srcPosition].buffer = const_cast<uint8_t*>(addrSrc.asData());
    vec[2 + srcPosition].len = 4;
    vec[3 - srcPosition].buffer = const_cast<uint8_t*>(addrDst.asData());
    vec[3 - srcPosition].len = 4;
    vec[4].buffer = &protocol;
    vec[4].len = 1;

    return fnvHash(vec, 5);
}

} // namespace snet::layers
