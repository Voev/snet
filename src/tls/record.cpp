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
    : Record(RecordType::Invalid)
{
}

Record::Record(RecordType type) noexcept
    : type_(type)
    , version_()
    , currentLength_(0)
    , expectedLength_(0)
    , state_(State::Empty)
{
    // Buffers start zeroed; spans are empty (size 0), pointing at the buffers
    // so getPlaintext().data() / getCiphertext().data() are never nullptr.
    std::memset(ciphertextBuffer_.data(), 0, ciphertextBuffer_.size());
    std::memset(plaintextBuffer_.data(), 0, plaintextBuffer_.size());
    ciphertext_ = {ciphertextBuffer_.data(), 0};
    plaintext_ = {plaintextBuffer_.data(), 0};
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
    state_ = State::Empty;
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
    casket::ThrowIfTrue(recordLength == 0, "Received an empty record");

    expectedLength_ = recordLength;
    currentLength_ = 0; // fresh assembly
    state_ = State::Reading;
}

size_t Record::serializeHeader(nonstd::span<uint8_t> output)
{
    casket::ThrowIfTrue(output.size() < TLS_HEADER_SIZE, "Output buffer is too small");
    casket::ThrowIfTrue(expectedLength_ > std::numeric_limits<uint16_t>::max(), "Record length overflows uint16_t");

    output[0] = static_cast<uint8_t>(type_);
    output[1] = version_.majorVersion();
    output[2] = version_.minorVersion();

    const uint16_t recordLength = static_cast<uint16_t>(expectedLength_);
    output[3] = casket::get_byte<0>(recordLength);
    output[4] = casket::get_byte<1>(recordLength);
    return TLS_HEADER_SIZE;
}

size_t Record::initPlaintext(nonstd::span<const uint8_t> plaintext)
{
    casket::ThrowIfTrue(plaintext.size() > (plaintextBuffer_.size() - dataStartOffset_),
                        "Plaintext does not fit in plaintext buffer");

    std::memcpy(plaintextBuffer_.data() + dataStartOffset_, plaintext.data(), plaintext.size());

    plaintext_ = {plaintextBuffer_.data(), dataStartOffset_ + plaintext.size()};
    expectedLength_ = plaintext_.size();
    currentLength_ = expectedLength_;
    state_ = State::Writing;
    return plaintext_.size();
}

size_t Record::initCiphertext(nonstd::span<const uint8_t> data) noexcept
{
    if (currentLength_ >= expectedLength_ && expectedLength_ > 0)
        return 0; // already fully assembled

    if (currentLength_ == 0 && expectedLength_ <= data.size())
    {
        // zero-copy
        ciphertext_ = {data.data(), expectedLength_};
        currentLength_ = expectedLength_;
        state_ = State::Read;
        return expectedLength_;
    }

    const auto copiedLength = std::min(expectedLength_ - currentLength_, data.size());
    if (copiedLength == 0)
        return 0;

    std::memcpy(ciphertextBuffer_.data() + currentLength_, data.data(), copiedLength);
    currentLength_ += copiedLength;
    ciphertext_ = {ciphertextBuffer_.data(), currentLength_};
    if (currentLength_ == expectedLength_)
        state_ = State::Read;
    return copiedLength;
}

void Record::setPlaintextLength(size_t len) noexcept
{
    assert(len <= plaintextBuffer_.size());
    plaintext_ = {plaintext_.data(), len};
}

void Record::markDecrypted(nonstd::span<uint8_t> pt) noexcept
{
    plaintext_ = pt;
    state_ = State::Decrypted;
}

void Record::markEncrypted(nonstd::span<const uint8_t> ct) noexcept
{
    ciphertext_ = ct;
    expectedLength_ = ct.size();
    currentLength_ = ct.size();
    state_ = State::Encrypted;
}

nonstd::span<uint8_t> Record::mutableCiphertext() noexcept
{
    return {const_cast<uint8_t*>(ciphertext_.data()), ciphertext_.size()};
}

std::error_code Record::deserializeHandshake(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo) noexcept
{
    HandshakeMessage msg;
    std::error_code ec{make_error_code(DecodeError::None)};

    ec = HandshakeMessage::deserialize(input, metaInfo, msg);
    if (!ec)
        handshake_ = std::move(msg);
    return ec;
}

inline ProtocolVersion GetRecordVersion(const HandshakeType type, const Session& session) noexcept
{
    return (type == HandshakeType::ClientHelloCode) ? ProtocolVersion::TLSv1_0 : session.getRecordVersion();
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
    currentLength_ = expectedLength_;
    state_ = session.canDecrypt(sideIndex) ? State::Encrypting : State::Writing;
    return expectedLength_;
}

size_t Record::serializeChangeCipherSpec(const ProtocolVersion& version)
{
    plaintextBuffer_[0] = 0x01;
    expectedLength_ = 1;
    version_ = version;
    type_ = RecordType::ChangeCipherSpec;
    plaintext_ = {plaintextBuffer_.data(), 1};
    currentLength_ = 1;
    state_ = State::Writing;
    return 1;
}

} // namespace snet::tls