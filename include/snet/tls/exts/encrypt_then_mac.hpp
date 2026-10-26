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
    // ---- ExtensionLike contract ----
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::EncryptThenMac;
    }

    bool empty() const noexcept
    {
        // Must be encoded when present (that's how the peer learns it's on).
        return false;
    }

    std::size_t serialize(Side /*side*/, nonstd::span<uint8_t> /*output*/) const noexcept
    {
        // RFC 7366: extension_data is empty.
        return 0;
    }

    // ---- ctors ----
    EncryptThenMAC() noexcept = default;

    // ---- parse ----
    /// Accepts only an empty body. Returns LengthOutOfRange otherwise.
    utils::DecodeError deserialize(Side /*side*/, nonstd::span<const uint8_t> input) noexcept
    {
        return input.empty() ? utils::DecodeError::None : utils::DecodeError::LengthOutOfRange;
    }
};

} // namespace snet::tls