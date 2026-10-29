#include <cassert>
#include <cstring>
#include <limits>

#include <snet/tls/record.hpp>
#include <snet/tls/session.hpp>

#include <snet/utils/decode_error.hpp>

#include <casket/utils/exception.hpp>

using namespace snet::utils;

namespace snet::tls
{

Record::Record() noexcept
{
    reset();
}

void Record::reset() noexcept
{
    type_ = RecordType::Invalid;
    version_ = ProtocolVersion();

    std::memset(plaintextBuffer_.data(), 0, plaintextBuffer_.size());
    plaintext_ = {plaintextBuffer_.data(), 0};

    std::memset(ciphertextBuffer_.data(), 0, ciphertextBuffer_.size());
    ciphertext_ = {ciphertextBuffer_.data(), 0};

    currentLength_ = 0;
    expectedLength_ = 0;
    dataStartOffset_ = 0;

    isPlaintext_ = false;
    mustBeEncrypted_ = false;
}

void Record::deserializeHeader(nonstd::span<const uint8_t> data)
{
    casket::ThrowIfTrue(data.size() < TLS_HEADER_SIZE, "TLS record header truncated");

    casket::ThrowIfTrue(data[0] < 20 || data[0] > 23, "TLS record type had unexpected value");
    type_ = static_cast<RecordType>(data[0]);

    casket::ThrowIfTrue(data[1] != 3 || data[2] >= 4, "TLS record version had unexpected value");
    version_ = ProtocolVersion(data[1], data[2]);

    const size_t recordLength = casket::make_uint16(data[3], data[4]);
    casket::ThrowIfTrue(recordLength > MAX_CIPHERTEXT_SIZE, "Received a record that exceeds maximum size");
    casket::ThrowIfTrue(recordLength == 0, "Received a empty record");
    expectedLength_ = recordLength;
    currentLength_  = 0;
}

size_t Record::serializeHeader(nonstd::span<uint8_t> output)
{
    casket::ThrowIfTrue(output.size() < TLS_HEADER_SIZE, "Output buffer is too small");
    casket::ThrowIfTrue(expectedLength_ > std::numeric_limits<uint16_t>::max(), "Record length overflows uint16_t");

    output[0] = static_cast<uint8_t>(type_);

    output[1] = version_.majorVersion();
    output[2] = version_.minorVersion();

    assert(expectedLength_ < std::numeric_limits<uint16_t>::max());
    uint16_t recordLength = static_cast<uint16_t>(expectedLength_);
    output[3] = casket::get_byte<0>(recordLength);
    output[4] = casket::get_byte<1>(recordLength);

    return TLS_HEADER_SIZE;
}

size_t Record::initCiphertext(nonstd::span<const uint8_t> data) noexcept
{
    if (currentLength_ >= expectedLength_ && expectedLength_ > 0)
    {
        return 0;
    }

    if (currentLength_ == 0 && expectedLength_ <= data.size())
    {
        // zero-copy
        ciphertext_ = {data.data(), expectedLength_};
        currentLength_ = expectedLength_;
        return expectedLength_;
    }

    const auto copiedLength = std::min(expectedLength_ - currentLength_, data.size());
    if (copiedLength == 0)
    {
        return 0;
    }

    std::memcpy(ciphertextBuffer_.data() + currentLength_, data.data(), copiedLength);
    currentLength_ += copiedLength;
    ciphertext_ = {ciphertextBuffer_.data(), currentLength_};
    return copiedLength;
}

std::error_code Record::deserializeHandshake(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo) noexcept
{
    HandshakeMessage msg;
    std::error_code ec{make_error_code(DecodeError::None)};

    ec = HandshakeMessage::deserialize(input, metaInfo, msg);
    if (!ec)
    {
        handshake_ = std::move(msg);
    }
    return ec;
}

inline ProtocolVersion GetRecordVersion(const HandshakeType type, const Session& session) noexcept
{
    ProtocolVersion version;
    if (type == HandshakeType::ClientHelloCode)
    {
        version = ProtocolVersion::TLSv1_0;
    }
    else
    {
        version = session.getRecordVersion();
    }
    return version;
}

size_t Record::serializeHandshake(HandshakeMessage&& handshake, const int8_t sideIndex, const Session& session)
{
    handshake_ = std::move(handshake);
    auto buffer = nonstd::span(plaintextBuffer_);
    dataStartOffset_ = session.getWriteRecordOffset(sideIndex);
    expectedLength_ = handshake_.serialize(buffer.subspan(dataStartOffset_), session);
    expectedLength_ += dataStartOffset_;
    version_ = GetRecordVersion(handshake_.getType(), session);
    type_ = RecordType::Handshake;
    plaintext_ = {plaintextBuffer_.data(), expectedLength_};
    isPlaintext_ = true;
    mustBeEncrypted_ = session.canDecrypt(sideIndex);
    currentLength_ = expectedLength_;
    return expectedLength_;
}

size_t Record::serializeChangeCipherSpec(const ProtocolVersion& version)
{
    plaintextBuffer_[0] = 0x01;
    expectedLength_ = 1;
    version_ = version;
    type_ = RecordType::ChangeCipherSpec;
    plaintext_ = {plaintextBuffer_.data(), expectedLength_};
    isPlaintext_ = true;
    mustBeEncrypted_ = false;
    currentLength_ = expectedLength_;
    return expectedLength_;
}

} // namespace snet::tls