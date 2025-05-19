/// @file
/// @brief Declaration of the TLS record class.

#pragma once
#include <span>
#include <snet/tls/version.hpp>
#include <snet/tls/types.hpp>
#include <snet/utils/load_store.hpp>
#include <casket/utils/exception.hpp>

namespace snet::tls
{

struct plain_text_t
{
    RecordType type;
    ProtocolVersion version;
    uint16_t length;
    uint8_t* fragment;
};

typedef struct generic_block_cipher
{
    uint8_t* IV;
    uint8_t* content;
    uint8_t* mac;
    uint8_t* padding;
    uint8_t padding_length;
} generic_block_cipher_t;

typedef struct generic_stream_cipher
{
    uint8_t* content;
    uint8_t* mac;
} generic_stream_cipher_t;

typedef struct generic_aead_cipher
{
    uint8_t* nonce_explicit;
    uint8_t* content;
} generic_aead_cipher_t;

typedef struct tls_ciphertext
{
    RecordType type;
    ProtocolVersion version;
    unsigned short length;
    uint8_t* fragment;
    union
    {
        generic_block_cipher_t block_cipher;
        generic_stream_cipher_t stream_cipher;
        generic_aead_cipher_t aead_cipher;
    } fragment_;
} cipher_text_t;

typedef enum
{
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

struct Record
{
    int id;

    RecordType type;
    ProtocolVersion version;
    ssl_record_state_t state;
    size_t length;      ///< Record length according to header (with header).
    size_t current_len; ////< Record length according to header (with header).
    size_t decryptedLength;
    uint8_t ciphertextBuffer[MAX_CIPHERTEXT_SIZE];
    uint8_t plaintextBuffer[MAX_PLAINTEXT_SIZE];
    uint8_t* data;
    uint8_t* decrypted;
    uint8_t* next_iv;
    uint8_t is_reset;
    uint8_t is_decrypted;

    uint64_t seqnum;

    void unpackHeader()
    {
        state = TO_DECRYPT;

        casket::utils::ThrowIfTrue(data[0] < 20 || data[0] > 23, "TLS record type had unexpected value");
        casket::utils::ThrowIfTrue(data[1] != 3 || data[2] >= 4, "TLS record version had unexpected value");

        type = static_cast<RecordType>(data[0]);
        version = ProtocolVersion(data[1], data[2]);
    }

    void reset()
    {
        state = ssl_record_state_t::NULL_STATE;
        length = 0;
        current_len = 0;
        is_reset = 0;
        is_decrypted = 0;
        seqnum = 0;
    }
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