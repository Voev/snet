#pragma once
#include <array>
#include <cstdint>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/typedefs.hpp>
#include <snet/tls/extensions.hpp>

namespace snet::tls
{

/// @brief NewSessionTicket message for TLSv1.2 (RFC5077)
struct TLSv1NewSessionTicket final
{
    void deserialize(nonstd::span<const uint8_t> input);

    size_t serialize(nonstd::span<uint8_t> output) const;

    uint32_t ticketLifetime{0};
    nonstd::span<const uint8_t> ticket;
};

} // namespace snet::tls