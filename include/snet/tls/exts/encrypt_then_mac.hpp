#pragma once

#include <cstdint>

#include <casket/nonstd/span.hpp>

#include <snet/tls/exts/extension_code.hpp>
#include <snet/tls/types.hpp>
#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

/// Encrypt-then-MAC Extension (RFC 7366).
///
/// Empty extension: `extension_data` MUST be empty on both ClientHello and
/// ServerHello. Presence of the extension == feature enabled.
class EncryptThenMAC final
{
public:
    /// @brief Gets the wire code for this extension.
    /// @return ExtensionCode::EncryptThenMac.
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::EncryptThenMac;
    }

    /// @brief Checks whether the extension has an empty body.
    /// @retval false Always; the extension must be encoded when present so
    ///         the peer learns that EtM is enabled.
    bool empty() const noexcept
    {
        return false;
    }

    /// @brief Serializes the extension into @p output.
    /// @param[in] side   Side (Client or Server); unused.
    /// @param[in] output Destination buffer; unused, body is empty.
    /// @return 0 -- RFC 7366 defines an empty `extension_data`.
    std::size_t serialize(Side side, nonstd::span<uint8_t> output) const noexcept
    {
        (void)side;
        (void)output;
        return 0;
    }

    /// @brief Default constructor.
    EncryptThenMAC() noexcept = default;

    /// @brief Parses the extension body from @p input.
    /// @param[in] side  Side (Client or Server); unused, body must be empty.
    /// @param[in] input Wire bytes of the extension_data field.
    /// @return DecodeError::None if @p input is empty,
    ///         DecodeError::LengthOutOfRange otherwise.
    utils::DecodeError deserialize(Side side, nonstd::span<const uint8_t> input) noexcept
    {
        (void)side;
        return input.empty() ? utils::DecodeError::None : utils::DecodeError::LengthOutOfRange;
    }
};

} // namespace snet::tls