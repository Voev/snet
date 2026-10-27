#pragma once

#include <cstdint>
#include <system_error>

#include <casket/nonstd/span.hpp>
#include <snet/utils/data_writer.hpp>

namespace snet::tls
{

class Session;

/// @brief TLS ServerHelloDone handshake message (TLS 1.2: RFC 5246 §7.4.5).
///
/// Sent by the server to indicate that it has finished sending its hello
/// messages and associated extensions. The message has an empty body
/// (zero bytes). Not used in TLS 1.3.
struct ServerHelloDone final
{
    /// @brief Default constructor.
    ServerHelloDone() noexcept = default;

    /// @brief Parses the ServerHelloDone body into `*this`.
    /// @param[in] input Wire bytes of the ServerHelloDone body; must be empty.
    /// @return `std::error_code` (`0` on success).
    ///         `DecodeError::LengthOutOfRange` if @p input is non-empty.
    /// @note `noexcept`.
    std::error_code deserialize(nonstd::span<const uint8_t> input) noexcept
    {
        if (!input.empty())
        {
            return utils::make_error_code(utils::DecodeError::LengthOutOfRange);
        }
        return {};
    }

    /// @brief Serializes the message into @p output.
    /// @param[in] output  Destination buffer; unused (empty message).
    /// @param[in] session Session context; unused (empty message).
    /// @return Always `0` (empty payload).
    /// @note `noexcept`.
    std::size_t serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept
    {
        (void)output;
        (void)session;
        return 0;
    }
};

} // namespace snet::tls