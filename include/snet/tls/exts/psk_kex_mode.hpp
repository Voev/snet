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

/// @brief PSK key exchange modes (RFC 8446 §4.2.9).
///
/// Wire format: `<1-byte length> <mode byte>*`.
/// Known modes: 0 = psk_ke, 1 = psk_dhe_ke. Unknown modes are rejected.
enum class PskKeyExchangeMode : std::uint8_t
{
    PskKe = 0,    ///< PSK-only key establishment.
    PskDheKe = 1, ///< PSK with (EC)DHE key establishment.
};

/// @brief Checks whether @p m is a known PSK key exchange mode.
/// @param[in] m Mode to check.
/// @retval true  Known mode.
/// @retval false Unknown mode.
constexpr bool isValidPskKeyExchangeMode(PskKeyExchangeMode m) noexcept
{
    switch (m)
    {
    case PskKeyExchangeMode::PskKe:
    case PskKeyExchangeMode::PskDheKe:
        return true;
    }
    return false;
}

/// @brief PSK Key Exchange Modes extension (RFC 8446 §4.2.9).
///
/// Carries a list of `PskKeyExchangeMode` values. Storage is a flat
/// `std::vector<PskKeyExchangeMode>` (1 byte per element); capacity is
/// reused across handshakes via `deserialize` on a pre-populated instance.
class PskKeyExchangeModes final
{
public:
    /// @brief Gets the wire code for this extension.
    /// @return ExtensionCode::PskKeyExchangeModes.
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::PskKeyExchangeModes;
    }

    /// @brief Checks whether the extension has an empty body.
    /// @retval true  No modes stored (extension is skipped).
    /// @retval false Otherwise.
    bool empty() const noexcept
    {
        return modes_.empty();
    }

    /// @brief Serializes the extension into @p output.
    /// @param[in] side   Side (Client or Server); unused.
    /// @param[in] output Destination buffer; must hold `1 + modes_.size()` bytes.
    /// @return Bytes written on success, `kSerializationFailed` if @p output
    ///         is too small, the mode list is empty, or it exceeds 255 bytes.
    std::size_t serialize(Side side, nonstd::span<uint8_t> output) const noexcept
    {
        (void)side;
        const std::size_t n = modes_.size();
        if (n == 0 || n > 255)
        {
            return kSerializationFailed;
        }

        if (output.size_bytes() < 1 + n)
        {
            return kSerializationFailed;
        }

        output[0] = static_cast<std::uint8_t>(n);
        for (std::size_t i = 0; i < n; ++i)
        {
            output[1 + i] = static_cast<std::uint8_t>(modes_[i]);
        }
        return 1 + n;
    }

    /// @brief Default constructor.
    PskKeyExchangeModes() noexcept = default;

    /// @brief Constructs from an existing list of modes.
    /// @param[in] modes Supported modes; order is preserved.
    explicit PskKeyExchangeModes(std::vector<PskKeyExchangeMode> modes) noexcept
        : modes_(std::move(modes))
    {
    }

    /// @brief Parses the extension body from @p input.
    /// @param[in] side  Side (Client or Server); unused.
    /// @param[in] input Wire bytes of the extension_data field.
    /// @return DecodeError::None on success;
    ///         NotEnoughBytes / LengthOutOfRange / TrailingBytes on
    ///         malformed input; AllocationFailed on allocation failure.
    ///         Unknown mode values are rejected with LengthOutOfRange.
    ///         On failure the object is left empty (strong guarantee).
    utils::DecodeError deserialize(Side side, nonstd::span<const uint8_t> input) noexcept
    {
        (void)side;

        modes_.clear();

        utils::DataReader reader("PskKeyExchangeModes", input);
        const std::uint8_t len = reader.get_byte();
        if (!reader.ok())
            return reader.take_error();
        if (len == 0 || len != reader.remaining_bytes())
            return utils::DecodeError::LengthOutOfRange;

        try
        {
            modes_.reserve(len);
        }
        catch (...)
        {
            return utils::DecodeError::AllocationFailed;
        }

        for (std::size_t i = 0; i < len; ++i)
        {
            const auto raw = static_cast<PskKeyExchangeMode>(reader.get_byte());
            if (!reader.ok())
            {
                modes_.clear();
                return reader.take_error();
            }
            if (!isValidPskKeyExchangeMode(raw))
            {
                modes_.clear();
                return utils::DecodeError::LengthOutOfRange;
            }
            try
            {
                modes_.push_back(raw);
            }
            catch (...)
            {
                modes_.clear();
                return utils::DecodeError::AllocationFailed;
            }
        }
        reader.assert_done();
        return reader.take_error();
    }

    /// @brief Gets the list of stored modes in wire order.
    /// @return View over the owned vector; empty means "not encoded".
    nonstd::span<const PskKeyExchangeMode> modes() const noexcept
    {
        return {modes_.data(), modes_.size()};
    }

private:
    std::vector<PskKeyExchangeMode> modes_; ///< Stored modes, wire order preserved.
};

} // namespace snet::tls