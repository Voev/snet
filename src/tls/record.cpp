#include <cstring>
#include <snet/tls/record.hpp>

#include <casket/utils/exception.hpp>

namespace snet::tls
{

void Record::reset()
{
    type = RecordType::Invalid;
    version = ProtocolVersion();

    std::memset(payloadBuffer.data(), 0, payloadBuffer.size());
    std::memset(decryptedBuffer.data(), 0, decryptedBuffer.size());

    payload = nullptr;

    currentLength = 0;
    expectedLength = 0;
    isDecrypted_ = false;
}

void Record::deserializeHeader(nonstd::span<const uint8_t> data)
{
    casket::ThrowIfTrue(data[0] < 20 || data[0] > 23, "TLS record type had unexpected value");
    type = static_cast<RecordType>(data[0]);

    casket::ThrowIfTrue(data[1] != 3 || data[2] >= 4, "TLS record version had unexpected value");
    version = ProtocolVersion(data[1], data[2]);

    const size_t recordLength = casket::make_uint16(data[3], data[4]);
    casket::ThrowIfTrue(recordLength > MAX_CIPHERTEXT_SIZE, "Received a record that exceeds maximum size");
    casket::ThrowIfTrue(recordLength == 0, "Received a empty record");
    expectedLength = recordLength + TLS_HEADER_SIZE;
}

size_t Record::initPayload(nonstd::span<const uint8_t> data)
{
    if (currentLength > 0 || expectedLength > data.size())
    {
        auto copiedLength = std::min(expectedLength - currentLength, data.size());
        payload = payloadBuffer.data();

        std::memcpy(payloadBuffer.data() + currentLength, data.data(), copiedLength);
        currentLength += copiedLength;
        return copiedLength;
    }
    else
    {
        payload = data.data();
        currentLength += expectedLength;
        return expectedLength;
    }
}

} // namespace snet::tls