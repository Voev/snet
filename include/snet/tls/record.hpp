/// @file
/// @brief Declaration of the TLS record class.

#pragma once
#include <span>
#include <array>
#include <variant>
#include <snet/tls/alert.hpp>
#include <snet/tls/version.hpp>
#include <snet/tls/types.hpp>
#include <snet/utils/load_store.hpp>

#include <snet/tls/msg/client_hello.hpp>
#include <snet/tls/msg/server_hello.hpp>
#include <snet/tls/msg/encrypted_extensions.hpp>
#include <snet/tls/msg/tls13_certificate.hpp>

#include <casket/utils/exception.hpp>

namespace snet::tls
{

struct HandshakeMessage
{
    HandshakeType type;
    msg::ClientHello clientHello;
    msg::ServerHello serverHello;
    msg::EncryptedExtensions encryptedExtensions;
    msg::TLSv13Certificate serverCertificate;
};

struct Record
{
    Record()
        : type(RecordType::Invalid)
        , payload(nullptr)
        , currentLength(0)
        , expectedLength(0)
        , decryptedLength(0)
        , isDecrypted_(false)
    {
    }

    void deserializeHeader(std::span<const uint8_t> data);

    size_t initPayload(std::span<const uint8_t> data);

    size_t packHandshake(const HandshakeMessage& handshake, std::span<uint8_t> buffer);

    size_t pack(const HandshakeMessage& handshake, std::span<uint8_t> buffer);

    void reset();

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

class RecordPool
{
public:
    RecordPool(size_t initial_size)
    {
        for (size_t i = 0; i < initial_size; ++i)
        {
            records_.emplace_back(new Record());
            free_records_.push_back(records_.back().get());
        }
    }

    ~RecordPool() = default;

    Record* acquire()
    {

        if (free_records_.empty())
        {
            // Если нет свободных записей, создаем новую
            records_.emplace_back(new Record());
            Record* record = records_.back().get();
            record->reset();
            return record;
        }

        Record* record = free_records_.back();
        free_records_.pop_back();
        record->reset();
        return record;
    }

    void release(Record* record)
    {
        record->reset();
        free_records_.push_back(record);
    }

    size_t size() const
    {
        return records_.size();
    }

    size_t available() const
    {
        return free_records_.size();
    }

private:
    std::vector<std::unique_ptr<Record>> records_;
    std::vector<Record*> free_records_;
};

} // namespace snet::tls