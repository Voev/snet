#pragma once

#include <cstdint>

#include <casket/nonstd/span.hpp>

#include <snet/tls/exts/extension_code.hpp>
#include <snet/tls/types.hpp>
#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

/// Record Size Limit (RFC 8449).
///
/// Carries a single `uint16_t` value: the maximum plaintext record size the
/// peer is willing to receive. Valid range is 64 .. 2^14 + 1.
class RecordSizeLimit final
{
public:
    /// @brief Minimum allowed limit, inclusive (RFC 8449 §4).
    static constexpr std::uint16_t kMinLimit = 64;

    /// @brief Maximum allowed limit, inclusive: 2^14 + 1 (encrypted content type byte).
    static constexpr std::uint16_t kMaxLimit = 16385;

    /// @brief Gets the wire code for this extension.
    /// @return ExtensionCode::RecordSizeLimit.
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::RecordSizeLimit;
    }

    /// @brief Checks whether the extension has an empty body.
    /// @retval true  `limit_ == 0` (uninitialized / disabled).
    /// @retval false Otherwise.
    bool empty() const noexcept
    {
        return limit_ == 0;
    }

    /// @brief Serializes the extension into @p output.
    /// @param[in] side   Side (Client or Server); unused.
    /// @param[in] output Destination buffer; must hold at least 2 bytes.
    /// @return 2 on success, 0 if @p output is too small.
    std::size_t serialize(Side side, nonstd::span<uint8_t> output) const noexcept
    {
        (void)side;

        if (output.size_bytes() < 2)
        {
            return kSerializationFailed;
        }

        output[0] = casket::get_byte<0>(limit_);
        output[1] = casket::get_byte<1>(limit_);
        return 2;
    }

    RecordSizeLimit() noexcept = default;

    /// @brief Constructs from a limit value.
    /// @param[in] limit Record size limit; must be in [64, 16385].
    /// @note No validation is performed here (the ctor is `noexcept`).
    ///       Validation is the caller's responsibility.
    explicit RecordSizeLimit(std::uint16_t limit) noexcept
        : limit_(limit)
    {
    }

    /// @brief Parses the extension body from @p input.
    /// @param[in] side  Side (Client or Server); server-side range check applies.
    /// @param[in] input Wire bytes of the extension_data field.
    /// @return DecodeError::None on success;
    ///         DecodeError::LengthOutOfRange on bad length or out-of-range limit.
    utils::DecodeError deserialize(Side side, nonstd::span<const uint8_t> input) noexcept
    {
        limit_ = 0;

        utils::DataReader reader("record_size_limit", input);
        const std::uint16_t value = reader.get_uint16_t();
        if (!reader.ok())
            return reader.take_error();
        reader.assert_done();
        if (!reader.ok())
            return reader.take_error();

        if (value < kMinLimit)
            return utils::DecodeError::LengthOutOfRange;
        if (side == Side::Server && value > kMaxLimit)
            return utils::DecodeError::LengthOutOfRange;

        limit_ = value;
        return utils::DecodeError::None;
    }

    /// @brief Gets the record size limit.
    /// @return The limit in bytes; 0 means the extension is disabled.
    std::uint16_t limit() const noexcept
    {
        return limit_;
    }

private:
    std::uint16_t limit_{0}; ///< Record size limit in bytes; 0 == uninitialized.
};

} // namespace snet::tls