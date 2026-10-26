#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

#include <casket/nonstd/span.hpp>

#include <snet/tls/exts/extension_code.hpp>
#include <snet/tls/types.hpp>
#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

/// @brief Session Ticket Extension (RFC 5077).
///
/// The `extension_data` field is the opaque ticket itself (no length prefix,
/// no inner structure). An empty ticket means "client supports tickets" in
/// ClientHello or "server issued nothing / requests new handshake" in
/// ServerHello -- the RFC explicitly allows a zero-length ticket.
class SessionTicketExtension final
{
public:
    /// @brief Gets the wire code for this extension.
    /// @return ExtensionCode::SessionTicket.
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::SessionTicket;
    }

    /// @brief Checks whether the extension has an empty body.
    /// @retval false Always; RFC 5077 allows an empty ticket, and the
    ///         presence of the extension itself is the signal.
    bool empty() const noexcept
    {
        return false;
    }

    /// @brief Serializes the extension into @p output.
    /// @param[in] side   Side (Client or Server); unused.
    /// @param[in] output Destination buffer; must hold `ticket_.size()` bytes.
    /// @return Bytes written on success (`0` for an empty ticket),
    ///         `kSerializationFailed` if @p output is too small or the ticket
    ///         exceeds 65535 bytes.
    std::size_t serialize(Side side, nonstd::span<uint8_t> output) const noexcept
    {
        (void)side;

        const std::size_t n = ticket_.size();
        if (n > 0xFFFF)
        {
            return kSerializationFailed;
        }

        if (output.size_bytes() < n)
        {
            return kSerializationFailed;
        }

        if (n)
        {
            std::memcpy(output.data(), ticket_.data(), n);
        }
        return n;
    }

    /// @brief Default constructor; the ticket is empty.
    SessionTicketExtension() noexcept = default;

    /// @brief Constructs from an existing ticket.
    /// @param[in] ticket Raw ticket bytes (0..65535); moved into the object.
    explicit SessionTicketExtension(std::vector<std::uint8_t> ticket) noexcept
        : ticket_(std::move(ticket))
    {
    }

    /// @brief Parses the extension body from @p input.
    /// @param[in] side  Side (Client or Server); unused.
    /// @param[in] input Wire bytes of the extension_data field (opaque ticket).
    /// @return DecodeError::None on success; AllocationFailed on OOM.
    ///         An empty @p input is valid (client: support signal; server:
    ///         no ticket).
    utils::DecodeError deserialize(Side side, nonstd::span<const uint8_t> input) noexcept
    {
        (void)side;

        ticket_.clear();

        if (input.empty())
        {
            return utils::DecodeError::None;
        }

        try
        {
            ticket_.assign(input.begin(), input.end());
        }
        catch (...)
        {
            ticket_.clear();
            return utils::DecodeError::AllocationFailed;
        }
        return utils::DecodeError::None;
    }

    /// @brief Gets the raw ticket bytes.
    /// @return View over the owned buffer; empty means "no ticket / support only".
    nonstd::span<const std::uint8_t> ticket() const noexcept
    {
        return {ticket_.data(), ticket_.size()};
    }

private:
    std::vector<std::uint8_t> ticket_; ///< Raw session ticket (opaque, 0..65535 bytes).
};

} // namespace snet::tls