#pragma once
#include <casket/nonstd/span.hpp>
#include <vector>
#include <string_view>
#include <snet/tls/exts/extension.hpp>

namespace snet::tls
{

/**
 * Session Ticket Extension (RFC 5077)
 */
class SessionTicketExtension final : public Extension
{
public:
    static ExtensionCode staticType()
    {
        return ExtensionCode::SessionTicket;
    }

    ExtensionCode type() const override
    {
        return staticType();
    }

    SessionTicketExtension() = default;

    SessionTicketExtension(Side, nonstd::span<const uint8_t> input)
    {
        ticket_.assign(input.begin(), input.end());
    }

    size_t serialize(Side side, nonstd::span<uint8_t> output) const override
    {

        (void)side;
        (void)output;
        return 0;
    }

    bool empty() const override
    {
        return false;
    }

private:
    std::vector<uint8_t> ticket_;
};

} // namespace snet::tls