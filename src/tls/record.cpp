#include <cassert>
#include <cstring>

#include <snet/tls/record.hpp>

#include <casket/utils/exception.hpp>

namespace snet::tls
{

void Record::reset()
{
    type_ = RecordType::Invalid;
    version_ = ProtocolVersion();

    std::memset(plaintextBuffer_.data(), 0, plaintextBuffer_.size());
    std::memset(ciphertextBuffer_.data(), 0, ciphertextBuffer_.size());

    currentLength_ = 0;
    expectedLength_ = 0;
    isDecrypted_ = false;
}

void Record::deserializeHeader(nonstd::span<const uint8_t> data)
{
    casket::ThrowIfTrue(data[0] < 20 || data[0] > 23, "TLS record type had unexpected value");
    type_ = static_cast<RecordType>(data[0]);

    casket::ThrowIfTrue(data[1] != 3 || data[2] >= 4, "TLS record version had unexpected value");
    version_ = ProtocolVersion(data[1], data[2]);

    const size_t recordLength = casket::make_uint16(data[3], data[4]);
    casket::ThrowIfTrue(recordLength > MAX_CIPHERTEXT_SIZE, "Received a record that exceeds maximum size");
    casket::ThrowIfTrue(recordLength == 0, "Received a empty record");
    expectedLength_ = recordLength + TLS_HEADER_SIZE;
}

size_t Record::initPlaintext(nonstd::span<const uint8_t> plaintext)
{
    assert(plaintext.size() <= plaintextBuffer_.size());

    std::memcpy(plaintextBuffer_.data(), plaintext.data(), plaintext.size());
    plaintext_ = {plaintextBuffer_.data(), plaintext.size()};
    return plaintext_.size();
}

size_t Record::initPayload(nonstd::span<const uint8_t> data)
{
    if (currentLength_ > 0 || expectedLength_ > data.size())
    {
        auto copiedLength = std::min(expectedLength_ - currentLength_, data.size());

        std::memcpy(ciphertextBuffer_.data() + currentLength_, data.data(), copiedLength);
        currentLength_ += copiedLength;

        ciphertext_ = {ciphertextBuffer_.data(), currentLength_};
        return copiedLength;
    }
    else
    {
        ciphertext_ = {data.data(), expectedLength_};
        currentLength_ += expectedLength_;
        return expectedLength_;
    }
}

} // namespace snet::tls