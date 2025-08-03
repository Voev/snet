/// @file
/// @brief Declaration of the TLS record class.

#pragma once
#include <casket/nonstd/span.hpp>
#include <snet/tls/version.hpp>
#include <casket/utils/load_store.hpp>
#include <casket/utils/exception.hpp>

namespace snet::tls
{

class Record
{
public:
    friend class RecordLayer;

    Record()
        : type_(RecordType::Invalid)
        , currentLength_(0)
        , expectedLength_(0)
        , isDecrypted_(false)
    {
    }

    Record(const RecordType type)
        : type_(type)
        , currentLength_(0)
        , expectedLength_(0)
        , isDecrypted_(false)
    {
    }

    inline bool isFullyAssembled() const noexcept
    {
        return expectedLength_ == currentLength_;
    }

    inline RecordType getType() const noexcept
    {
        return type_;
    }

    inline ProtocolVersion getVersion() const noexcept
    {
        return version_;
    }

    inline uint16_t getLength() const noexcept
    {
        return currentLength_;
    }

    inline bool isDecrypted() const noexcept
    {
        return isDecrypted_;
    }

    inline nonstd::span<const uint8_t> getCiphertext() const noexcept
    {
        return ciphertext_;
    }

    inline nonstd::span<const uint8_t> getPlaintext() const noexcept
    {
        return plaintext_;
    }

    void reset();

    size_t initPlaintext(nonstd::span<const uint8_t> plaintext);

    size_t initPayload(nonstd::span<const uint8_t> data);

    void deserializeHeader(nonstd::span<const uint8_t> data);

private:
    RecordType type_;
    ProtocolVersion version_;
    std::array<uint8_t, MAX_CIPHERTEXT_SIZE> ciphertextBuffer_;
    std::array<uint8_t, MAX_PLAINTEXT_SIZE> plaintextBuffer_;
    size_t currentLength_;
    size_t expectedLength_;
    nonstd::span<const std::uint8_t> ciphertext_;
    nonstd::span<std::uint8_t> plaintext_;
    bool isDecrypted_;
};

} // namespace snet::tls