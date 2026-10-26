#pragma once

#include <cstdint>
#include <vector>

#include <casket/nonstd/span.hpp>

#include <snet/tls/exts/extension_code.hpp>
#include <snet/tls/types.hpp>
#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

/// @brief Safe Renegotiation Extension (RFC 5746).
///
/// Carries the `renegotiated_connection` field:
///   * empty (0 bytes) in the initial handshake;
///   * `<1-byte length> <verify_data>` on renegotiation.
/// The wire form is `<1-byte length> <bytes>` on both ClientHello and
/// ServerHello; for the initial handshake the length byte is 0.
class RenegotiationExtension final
{
public:
    /// @brief Gets the wire code for this extension.
    /// @return ExtensionCode::SafeRenegotiation.
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::SafeRenegotiation;
    }

    /// @brief Checks whether the extension has an empty body.
    /// @retval false Always; the extension is encoded even when `renegData_`
    ///         is empty (that is the initial-handshake form).
    bool empty() const noexcept
    {
        return false;
    }

    /// @brief Serializes the extension into @p output.
    /// @param[in] side   Side (Client or Server); unused.
    /// @param[in] output Destination buffer; must hold `1 + renegData_.size()` bytes.
    /// @return Bytes written on success, `kSerializationFailed` if @p output
    ///         is too small or the body exceeds 255 bytes.
    std::size_t serialize(Side side, nonstd::span<uint8_t> output) const noexcept
    {
        (void)side;

        if (renegData_.size() > 255)
            return kSerializationFailed;
        if (output.size_bytes() < 1 + renegData_.size())
            return kSerializationFailed;

        output[0] = static_cast<std::uint8_t>(renegData_.size());
        if (!renegData_.empty())
        {
            std::memcpy(output.data() + 1, renegData_.data(), renegData_.size());
        }
        return 1 + renegData_.size();
    }

    /// @brief Default constructor; `renegotiated_connection` is empty
    ///        (initial-handshake form).
    RenegotiationExtension() noexcept = default;

    /// @brief Constructs from an existing `renegotiated_connection` value.
    /// @param[in] renegData Raw bytes; size must be <= 255 (RFC 5746).
    /// @note No validation is performed here (the ctor is `noexcept`).
    ///       If @p renegData is longer than 255 bytes, `serialize` will fail
    ///       with `kSerializationFailed`.
    explicit RenegotiationExtension(std::vector<std::uint8_t> renegData) noexcept
        : renegData_(std::move(renegData))
    {
    }

    /// @brief Parses the extension body from @p input.
    /// @param[in] side  Side (Client or Server); unused.
    /// @param[in] input Wire bytes of the extension_data field.
    /// @return DecodeError::None on success;
    ///         DecodeError::NotEnoughBytes / LengthOutOfRange / TrailingBytes
    ///         on malformed input; AllocationFailed on allocation failure.
    ///         On failure the object is left with an empty body
    ///         (strong guarantee).
    utils::DecodeError deserialize(Side side, nonstd::span<const uint8_t> input) noexcept
    {
        (void)side;

        renegData_.clear();

        utils::DataReader reader("renegotiation_extension", input);
        const auto data = reader.get_span_length_and_value(1);
        if (!reader.ok())
            return reader.take_error();

        reader.assert_done();
        if (!reader.ok())
            return reader.take_error();

        try
        {
            renegData_.assign(data.begin(), data.end());
        }
        catch (...)
        {
            renegData_.clear();
            return utils::DecodeError::AllocationFailed;
        }
        return utils::DecodeError::None;
    }

    /// @brief Gets the raw `renegotiated_connection` bytes.
    /// @return View over the owned buffer; empty for the initial handshake.
    nonstd::span<const std::uint8_t> getRenegInfo() const noexcept
    {
        return {renegData_.data(), renegData_.size()};
    }

private:
    std::vector<std::uint8_t> renegData_; ///< `renegotiated_connection` bytes; 0..255 long.
};

} // namespace snet::tls