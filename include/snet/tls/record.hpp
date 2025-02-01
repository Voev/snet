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

} // namespace snet::tls