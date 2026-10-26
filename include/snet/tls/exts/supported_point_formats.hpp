#pragma once

#include <cstdint>
#include <vector>

#include <casket/nonstd/span.hpp>

#include <snet/tls/exts/extension_code.hpp>
#include <snet/tls/types.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

namespace snet::tls
{

/// EC point formats (RFC 4492 §5.1.2).
enum class ECPointFormat : std::uint8_t
{
    Uncompressed = 0,            ///< Uncompressed.
    AnsiX962CompressedPrime = 1, ///< ANSI X9.62 compressed (prime field).
    AnsiX962CompressedChar2 = 2, ///< ANSI X9.62 compressed (characteristic-2 field).
};

/// @brief Checks whether @p f is a known ECPointFormat value.
constexpr bool isValidECPointFormat(ECPointFormat f) noexcept
{
    switch (f)
    {
    case ECPointFormat::Uncompressed:
    case ECPointFormat::AnsiX962CompressedPrime:
    case ECPointFormat::AnsiX962CompressedChar2:
        return true;
    }
    return false;
}

/// Supported EC Point Formats extension (RFC 4492, obsolete in TLS 1.3).
///
/// Wire format: `<1-byte length> <format byte>*`. The length field is
/// 1 byte; an empty list is syntactically valid but semantically useless,
/// so `empty()` reports `true` only when `formats_` is empty.
class SupportedPointFormats final
{
public:
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::ECPointFormats;
    }

    /// @brief Checks whether the extension has an empty body.
    /// @retval true  No formats (extension is skipped).
    /// @retval false Otherwise.
    bool empty() const noexcept
    {
        return formats_.empty();
    }

    /// @brief Serializes the extension into @p output.
    /// @param[in] side   Side (Client or Server); unused.
    /// @param[in] output Destination buffer; must hold 1 + formats_.size() bytes.
    /// @return Bytes written on success, kSerializationFailed if @p output
    ///         is too small or the list does not fit a 1-byte length.
    std::size_t serialize(Side side, nonstd::span<uint8_t> output) const noexcept
    {
        (void)side;

        const std::size_t n = formats_.size();
        if (n > 255)
            return kSerializationFailed;
        if (output.size_bytes() < 1 + n)
            return kSerializationFailed;

        output[0] = static_cast<std::uint8_t>(n);
        for (std::size_t i = 0; i < n; ++i)
        {
            output[1 + i] = static_cast<std::uint8_t>(formats_[i]);
        }
        return 1 + n;
    }

    SupportedPointFormats() noexcept = default;

    /// @brief Constructs from an existing list of formats.
    /// @param[in] formats EC point formats; order is preserved.
    explicit SupportedPointFormats(std::vector<ECPointFormat> formats) noexcept
        : formats_(std::move(formats))
    {
    }

    /// @brief Parses the extension body from @p input.
    /// @param[in] side  Side (Client or Server); unused.
    /// @param[in] input Wire bytes of the extension_data field.
    /// @return DecodeError::None on success;
    ///         NotEnoughBytes / LengthOutOfRange / TrailingBytes on
    ///         malformed input. Unknown format bytes are rejected.
    utils::DecodeError deserialize(Side side, nonstd::span<const uint8_t> input) noexcept
    {
        (void)side;

        formats_.clear();

        utils::DataReader reader("ECPointFormats", input);

        const std::uint8_t len = reader.get_byte();
        if (!reader.ok())
            return reader.take_error();
        if (len != reader.remaining_bytes())
            return utils::DecodeError::LengthOutOfRange;

        try
        {
            formats_.reserve(len);
        }
        catch (...)
        {
            return utils::DecodeError::AllocationFailed;
        }

        for (std::size_t i = 0; i < len; ++i)
        {
            const auto raw = static_cast<ECPointFormat>(reader.get_byte());
            if (!reader.ok())
                return reader.take_error();
            if (!isValidECPointFormat(raw))
                return utils::DecodeError::LengthOutOfRange;
            try
            {
                formats_.push_back(raw);
            }
            catch (...)
            {
                formats_.clear();
                return utils::DecodeError::AllocationFailed;
            }
        }
        reader.assert_done();
        return reader.take_error();
    }

    /// @brief Gets the list of EC point formats in wire order.
    /// @return View over the owned vector; empty means "not encoded".
    nonstd::span<const ECPointFormat> getFormats() const noexcept
    {
        return {formats_.data(), formats_.size()};
    }

private:
    std::vector<ECPointFormat> formats_; ///< EC point formats, wire order preserved.
};

} // namespace snet::tls