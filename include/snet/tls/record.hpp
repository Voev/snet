/// @file
/// @brief Declaration of the TLS record class.

#pragma once
#include <casket/nonstd/span.hpp>
#include <snet/tls/version.hpp>
#include <casket/utils/load_store.hpp>
#include <casket/utils/exception.hpp>

namespace snet::tls
{

class Session;

class Record
{
public:
    /// @todo: use class RecordLayer
    friend class Session;

    Record()
        : type(RecordType::Invalid)
        , payload(nullptr)
        , currentLength(0)
        , expectedLength(0)
        , isDecrypted_(false)
    {
    }

    inline bool isFullyAssembled() const noexcept
    {
        return expectedLength == currentLength;
    }

    inline RecordType getType() const noexcept
    {
        return type;
    }

    inline ProtocolVersion getVersion() const noexcept
    {
        return version;
    }

    inline uint16_t getLength() const noexcept
    {
        return currentLength;
    }

    inline bool isDecrypted() const noexcept
    {
        return isDecrypted_;
    }

    inline nonstd::span<const uint8_t> getData() const noexcept
    {
        return {payload, currentLength};
    }

    inline nonstd::span<const uint8_t> getDecryptedData() const noexcept
    {
        return decryptedData;
    }

    void reset();

    size_t initPayload(nonstd::span<const uint8_t> data);

    void deserializeHeader(nonstd::span<const uint8_t> data);

private:
    RecordType type;
    ProtocolVersion version;
    std::array<uint8_t, MAX_CIPHERTEXT_SIZE> payloadBuffer;
    std::array<uint8_t, MAX_PLAINTEXT_SIZE> decryptedBuffer;
    const uint8_t* payload;
    size_t currentLength;
    size_t expectedLength;
    nonstd::span<const std::uint8_t> decryptedData;
    bool isDecrypted_;
};

} // namespace snet::tls