#pragma once

#include <casket/nonstd/span.hpp>
#include <casket/utils/exception.hpp>

#include <snet/tls/meta_info.hpp>

#include <snet/utils/data_reader.hpp>

#include <cstddef>
#include <cstdint>

namespace snet::tls
{

class Session;

/// @brief Represents a KeyUpdate message in TLS 1.3 protocol.
///
/// This is a post-handshake message sent by either peer to signal that
/// the sender is updating its sending cryptographic keys. It carries a
/// single byte: RequestUpdate (0 = update_not_requested, 1 = update_requested).
/// The receiver must respond with its own KeyUpdate if requestUpdate == 1.
struct KeyUpdate final
{
    enum class RequestUpdate : uint8_t
    {
        UpdateNotRequested = 0,
        UpdateRequested = 1,
    };

    /// @brief Whether the peer is asked to update its keys as well.
    RequestUpdate requestUpdate{RequestUpdate::UpdateNotRequested};

    KeyUpdate() = default;

    explicit KeyUpdate(RequestUpdate ru) noexcept
        : requestUpdate(ru)
    {
    }

    /// @brief Deserialize a KeyUpdate message into *this.
    ///
    /// @param[in] input Raw bytes. Must be exactly 1 byte.
    ///
    /// @return std::error_code{} on success; error on malformed input.
    ///
    /// @note noexcept: errors are reported via error_code, not exceptions.
    std::error_code deserialize(nonstd::span<const uint8_t> input) noexcept
    {
        if (input.size() != 1)
        {
            return utils::make_error_code(utils::DecodeError::NotEnoughBytes);
        }

        const auto value = static_cast<RequestUpdate>(input[0]);
        if (value != RequestUpdate::UpdateNotRequested && value != RequestUpdate::UpdateRequested)
        {
            return utils::make_error_code(utils::DecodeError::MalformedMessage);
        }

        requestUpdate = value;
        return {};
    }

    /// @brief Serialize the KeyUpdate message to a byte buffer.
    ///
    /// @param[in] output Buffer to write the serialized data to. Must be >= 1 byte.
    /// @param[in] session Session context for serialization (unused).
    ///
    /// @return Number of bytes written (always 1).
    ///
    /// @throws casket::Exception if output is too small.
    size_t serialize(nonstd::span<uint8_t> output, const Session& session) const
    {
        (void)session;
        casket::ThrowIfFalse(output.size() >= 1, "Output buffer too small for KeyUpdate");
        output[0] = static_cast<uint8_t>(requestUpdate);
        return 1;
    }

    /// @brief Serialized size of the KeyUpdate payload (always 1).
    static constexpr size_t serializedSize() noexcept
    {
        return 1;
    }

    bool operator==(const KeyUpdate& other) const noexcept
    {
        return requestUpdate == other.requestUpdate;
    }
    bool operator!=(const KeyUpdate& other) const noexcept
    {
        return !(*this == other);
    }
};

} // namespace snet::tls