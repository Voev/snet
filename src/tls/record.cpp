#include <cassert>
#include <cstring>
#include <limits>

#include <snet/tls/record.hpp>
#include <snet/tls/session.hpp>

#include <casket/utils/exception.hpp>

namespace snet::tls
{

void Record::reset()
{
    type_ = RecordType::Invalid;
    version_ = ProtocolVersion();

    std::memset(plaintextBuffer_.data(), 0, plaintextBuffer_.size());
    plaintext_ = plaintextBuffer_;

    std::memset(ciphertextBuffer_.data(), 0, ciphertextBuffer_.size());
    ciphertext_ = ciphertextBuffer_;

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

size_t Record::serializeHeader(nonstd::span<uint8_t> output)
{
    casket::ThrowIfTrue(output.size() < TLS_HEADER_SIZE, "Output buffer is too small");
    output[0] = static_cast<uint8_t>(type_);

    output[1] = version_.majorVersion();
    output[2] = version_.minorVersion();

    assert(expectedLength_ < std::numeric_limits<uint16_t>::max());
    uint16_t recordLength = static_cast<uint16_t>(expectedLength_);
    output[3] = casket::get_byte<0>(recordLength);
    output[4] = casket::get_byte<1>(recordLength);

    return TLS_HEADER_SIZE;
}

size_t Record::initPayload(nonstd::span<const uint8_t> data) noexcept
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

void Record::deserializeHandshake(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo)
{
    handshake_ = HandshakeMessage::deserialize(input, metaInfo);
}

size_t Record::serializeServerHello(ServerHello& serverHello, nonstd::span<uint8_t> output, const Session& session)
{
    handshake_ = HandshakeMessage(serverHello, HandshakeType::ServerHelloCode);
    expectedLength_ = handshake_.serialize(output, session);
    version_ = session.getVersion();
    type_ = RecordType::Handshake;

    return expectedLength_;
}

size_t Record::serializeEncryptedExtensions(EncryptedExtensions& encryptedExtensions, const Session& session)
{
    handshake_ = HandshakeMessage(encryptedExtensions, HandshakeType::EncryptedExtensionsCode);
    expectedLength_ = handshake_.serialize(plaintext_, session);
    version_ = session.getVersion();
    type_ = RecordType::Handshake;

    return expectedLength_;
}


} // namespace snet::tls