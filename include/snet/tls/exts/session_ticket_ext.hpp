#pragma once
#include <casket/nonstd/span.hpp>
#include <vector>
#include <string_view>
#include <snet/tls/exts/extension.hpp>

namespace snet::tls
{

/// @brief Session Ticket Extension (RFC 5077)
///
/// Implements the Session Ticket TLS extension as defined in RFC 5077.
/// This extension allows for the resumption of TLS sessions without
/// requiring session state to be stored on the server, by providing
/// an encrypted ticket that contains all necessary session information.
///
class SessionTicketExtension final : public Extension
{
public:
    /// @brief Get the static extension code for Session Ticket.
    ///
    /// @return ExtensionCode The extension code value for Session Ticket.
    static ExtensionCode staticType()
    {
        return ExtensionCode::SessionTicket;
    }

    /// @brief Get the extension type code.
    ///
    /// @return ExtensionCode The extension type code for this instance.
    ExtensionCode type() const override
    {
        return staticType();
    }

    /// @brief Default constructor for empty Session Ticket extension.
    SessionTicketExtension() = default;

    /// @brief Construct a Session Ticket extension from raw data.
    ///
    /// @param[in] side The side of the connection (client/server).
    /// @param[in] input Raw bytes containing the session ticket data.
    SessionTicketExtension(Side, nonstd::span<const uint8_t> input)
    {
        ticket_.assign(input.begin(), input.end());
    }

    /// @brief Serialize the extension to a byte buffer.
    ///
    /// @param[in] side The side of the connection (client/server).
    /// @param[in] output Buffer to write the serialized data to.
    ///
    /// @return size_t Number of bytes written to output buffer.
    size_t serialize(Side side, nonstd::span<uint8_t> output) const override
    {
        /// @todo: support it.
        (void)side;
        (void)output;
        return 0;
    }

    /// @brief Check if the extension is empty.
    ///
    /// @return bool Always returns false for Session Ticket extension.
    bool empty() const override
    {
        return false;
    }

private:
    std::vector<uint8_t> ticket_; ///< Raw session ticket data
};

} // namespace snet::tls