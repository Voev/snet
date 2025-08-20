#pragma once
#include <array>
#include <cstdint>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/typedefs.hpp>
#include <snet/tls/extensions.hpp>

namespace snet::tls
{

struct TLSv13NewSessionTicket final
{
    void deserialize(nonstd::span<const uint8_t> input);

    size_t serialize(nonstd::span<uint8_t> output) const;

    uint32_t ticketLifetime{0};
    uint32_t ticketAgeAdd{0};
    nonstd::span<const uint8_t> ticketNonce;
    nonstd::span<const uint8_t> ticket;
    nonstd::span<const uint8_t> extsData;
    Extensions* extensions{nullptr};
};

} // namespace snet::tls