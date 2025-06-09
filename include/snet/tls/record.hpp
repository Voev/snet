/// @file
/// @brief Declaration of the TLS record class.

#pragma once
#include <span>
#include <snet/tls/version.hpp>
#include <snet/utils/load_store.hpp>
#include <casket/utils/exception.hpp>

namespace snet::tls
{

class Record
{
public:
    Record()
        : type(RecordType::Invalid)
        , payload(nullptr)
        , currentLength(0)
        , expectedLength(0)
        , decryptedLength(0)
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

    inline std::span<const uint8_t> getData() const noexcept
    {
        return {payload, currentLength};
    }

    inline std::span<const uint8_t> getDecryptedData() const noexcept
    {
        return {decryptedBuffer.data(), decryptedLength};
    }

    void reset();


    size_t initPayload(std::span<const uint8_t> data);

        void deserializeHeader(std::span<const uint8_t> data);


    RecordType type;
    ProtocolVersion version;
    std::array<uint8_t, MAX_CIPHERTEXT_SIZE> payloadBuffer;
    std::array<uint8_t, MAX_PLAINTEXT_SIZE> decryptedBuffer;
    const uint8_t* payload;
    size_t currentLength;
    size_t expectedLength;
    size_t decryptedLength;
    bool isDecrypted_;
};

} // namespace snet::tls