#pragma once
#include <span>
#include <snet/tls/version.hpp>

#include <snet/utils/load_store.hpp>
#include <casket/utils/exception.hpp>

namespace snet::tls
{

class Record final
{
public:
    explicit Record(RecordType type, ProtocolVersion version, std::span<const uint8_t> data)
        : type_(type)
        , version_(version)
        , data_(data)
    {
    }

    RecordType type() const
    {
        return type_;
    }

    ProtocolVersion version() const
    {
        return version_;
    }

    std::span<const uint8_t> data() const
    {
        return data_;
    }

    size_t totalLength() const
    {
        return TLS_HEADER_SIZE + data_.size_bytes();
    }

private:
    RecordType type_;
    ProtocolVersion version_;
    std::span<const uint8_t> data_;
};

inline Record readRecord(const int8_t sideIndex, std::span<const uint8_t> inputBytes)
{
    using namespace casket::utils;

    (void)sideIndex;

    ThrowIfTrue(inputBytes.size() < TLS_HEADER_SIZE, "Inappropriate header size");
    ThrowIfTrue(inputBytes[0] < 20 || inputBytes[0] > 23, "TLS record type had unexpected value");
    ThrowIfTrue(inputBytes[1] != 3 || inputBytes[2] >= 4,
                "TLS record version had unexpected value");

    RecordType recordType = static_cast<RecordType>(inputBytes[0]);
    const ProtocolVersion recordVersion(inputBytes[1], inputBytes[2]);
    const size_t recordSize =
        utils::make_uint16(inputBytes[TLS_HEADER_SIZE - 2], inputBytes[TLS_HEADER_SIZE - 1]);

    ThrowIfTrue(recordSize > MAX_CIPHERTEXT_SIZE, "Received a record that exceeds maximum size");
    ThrowIfTrue(recordSize > inputBytes.size(), "Incorrect record length");
    ThrowIfTrue(recordSize == 0, "Received a empty record");

    return Record(recordType, recordVersion, inputBytes.subspan(TLS_HEADER_SIZE, recordSize));
}

} // namespace snet::tls