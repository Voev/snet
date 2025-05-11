/// @file
/// @brief Declaration of the TLS record class.

#pragma once
#include <span>
#include <array>
#include <variant>
#include <cassert>
#include <queue>
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
    class Handle
    {
    public:
        explicit Handle(RecordPool& pool)
            : pool_(pool)
            , record_(pool.acquire())
        {
        }

        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;

        Handle(Handle&& other) noexcept
            : pool_(other.pool_)
            , record_(other.record_)
        {
            other.record_ = nullptr;
        }

        ~Handle()
        {
            if (record_)
            {
                pool_.release(record_);
            }
        }

        Record* release()
        {
            Record* ptr = record_;
            record_ = nullptr;
            return ptr;
        }

        Record* get() const
        {
            return record_;
        }

        Record* operator->() const
        {
            return record_;
        }

        Record& operator*() const
        {
            return *record_;
        }

    private:
        RecordPool& pool_;
        Record* record_;
    };

    RecordPool(size_t fixed_size = 1024)
        : records_(fixed_size)
    {
        for (auto& record : records_)
        {
            record = std::make_unique<Record>();
            free_records_.push_back(record.get());
        }
    }

    ~RecordPool() = default;

    Record* acquire() noexcept
    {
        if (free_records_.empty())
        {
            return nullptr;
        }

        Record* record = free_records_.back();
        free_records_.pop_back();
        record->reset();
        return record;
    }

    void release(Record* record) noexcept
    {
        if (!record)
            return;

        assert(is_from_pool(record));
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

    Handle createHandle()
    {
        return Handle(*this);
    }

private:
    bool is_from_pool(Record* record) const
    {
        auto it =
            std::find_if(records_.begin(), records_.end(), [record](const auto& ptr) { return ptr.get() == record; });
        return it != records_.end();
    }

private:
    std::vector<std::unique_ptr<Record>> records_;
    std::vector<Record*> free_records_;
};

using RecordList = std::queue<RecordPool::Handle>;

} // namespace snet::tls