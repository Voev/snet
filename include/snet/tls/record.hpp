/// @file
/// @brief Declaration of the TLS record class.

#pragma once
#include <span>
#include <snet/tls/version.hpp>
#include <snet/utils/load_store.hpp>
#include <casket/utils/exception.hpp>

namespace snet::tls
{

/// @brief Class representing a TLS record.
class Record final
{
public:
    /// @brief Constructor with record type, protocol version, and data.
    /// @param type The record type.
    /// @param version The protocol version.
    /// @param data The record data.
    explicit Record(RecordType type, ProtocolVersion version, std::span<const uint8_t> data)
        : type_(type)
        , version_(std::move(version))
        , data_(data)
    {
    }

    /// @brief Gets the record type.
    /// @return The record type.
    RecordType type() const noexcept
    {
        return type_;
    }

    /// @brief Gets the protocol version.
    /// @return The protocol version.
    const ProtocolVersion& version() const noexcept
    {
        return version_;
    }

    /// @brief Gets the record data.
    /// @return The record data.
    std::span<const uint8_t> data() const noexcept
    {
        return data_;
    }

    /// @brief Gets the total length of the record.
    /// @return The total length of the record.
    size_t totalLength() const
    {
        return TLS_HEADER_SIZE + data_.size_bytes();
    }

private:
    RecordType type_;
    ProtocolVersion version_;
    std::span<const uint8_t> data_;
};

struct protocol_version_t {
    uint8_t major;
    uint8_t minor;
};

struct plain_text_t {
    uint8_t c_type;
    protocol_version_t version;
    uint16_t length;
    uint8_t* fragment;
};

typedef struct compressed_text {
    uint8_t c_type;
    protocol_version_t version;
    uint16_t length;
    uint8_t* fragment;
} compressed_text_t;

typedef struct generic_block_cipher {
    uint8_t *IV;
    uint8_t *content;
    uint8_t *mac;
    uint8_t *padding;
    uint8_t padding_length;
} generic_block_cipher_t;

typedef struct generic_stream_cipher {
    uint8_t *content;
    uint8_t *mac;
} generic_stream_cipher_t;

typedef struct generic_aead_cipher {
    uint8_t *nonce_explicit;
    uint8_t *content;
} generic_aead_cipher_t;

typedef struct tls_ciphertext {
    uint8_t c_type;
    protocol_version_t version;
    unsigned short length;
    union {
        generic_block_cipher_t block_cipher;
        generic_stream_cipher_t stream_cipher;
        generic_aead_cipher_t aead_cipher;
    } fragment;
} cipher_text_t;

typedef enum {
    TO_PACK_HEADER,
    TO_PACK_CONTENT,
    TO_APPEND_MAC,
    TO_ENCRYPT,
    WRITE_READY,
    TO_UNPACK_HEADER,
    TO_DECRYPT,
    TO_VERIFY_MAC,
    TO_UNPACK_CONTENT,
    READ_READY,

    NULL_STATE
} ssl_record_state_t;

typedef struct record {
    int id;
    struct thread_context *ctx;
    struct ssl_session *sess;

    ssl_record_state_t state;
    size_t length;
    size_t current_len;
    uint8_t buf[16 * 1024];
    uint8_t *decrypted;
    uint8_t mac_in[16 * 1024];
    uint8_t *data;
    uint8_t *next_iv;
    uint8_t is_reset;
    uint8_t is_received;
    uint8_t is_encrypted;
    uint8_t mac_buf[32];

    uint64_t seq_num;

    plain_text_t plain_text;
    cipher_text_t cipher_text;

    void reset() {
        state = ssl_record_state_t::NULL_STATE;
        length = 0;
        current_len = 0;
        is_reset = 0;
        is_received = 0;
        is_encrypted = 0;
        seq_num = 0;
        
        plain_text = plain_text_t{};
        cipher_text = cipher_text_t{};
    }

} record_t;


class RecordPool {
public:
    RecordPool(size_t initial_size) {
        for (size_t i = 0; i < initial_size; ++i) {
            records_.emplace_back(new record_t());
            free_records_.push_back(records_.back().get());
        }
    }

    ~RecordPool() = default;

    record_t* acquire() {

        if (free_records_.empty()) {
            // Если нет свободных записей, создаем новую
            records_.emplace_back(new record_t());
            record_t* record = records_.back().get();
            record->reset();
            return record;
        }
        
        record_t* record = free_records_.back();
        free_records_.pop_back();
        record->reset();
        return record;
    }

    void release(record_t* record) {
        record->reset();
        free_records_.push_back(record);
    }

    size_t size() const {
        return records_.size();
    }

    size_t available() const {
        return free_records_.size();
    }

private:
    std::vector<std::unique_ptr<record_t>> records_;
    std::vector<record_t*> free_records_;
};

} // namespace snet::tls