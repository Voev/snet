#include <snet/tls/msgs/tls13_new_session_ticket.hpp>

#include <cstring>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>
#include <snet/utils/decode_error.hpp>
#include <casket/utils/load_store.hpp>

namespace snet::tls
{

using snet::AppendLengthAndValue;
using snet::kSerializationFailed;

std::error_code TLSv13NewSessionTicket::deserialize(nonstd::span<const uint8_t> input) noexcept
{
    ticketLifetime = 0;
    ticketAgeAdd = 0;
    ticketNonce = {};
    ticket = {};
    extsData = {};

    utils::DataReader reader("TLSv1.3 NewSessionTicket", input);

    ticketLifetime = reader.get_uint32_t();
    if (!reader.ok())
        return reader.take_ec();

    ticketAgeAdd = reader.get_uint32_t();
    if (!reader.ok())
        return reader.take_ec();

    ticketNonce = reader.get_span_length_and_value(1);
    if (!reader.ok())
        return reader.take_ec();

    ticket = reader.get_span_length_and_value(2);
    if (!reader.ok())
        return reader.take_ec();
    if (ticket.empty())
        return utils::make_error_code(utils::DecodeError::LengthOutOfRange);

    const std::uint16_t extTotal = reader.peek_uint16_t();
    if (!reader.ok())
        return reader.take_ec();
    if (extTotal != reader.remaining_bytes() - 2)
    {
        return utils::make_error_code(utils::DecodeError::LengthOutOfRange);
    }

    extsData = reader.get_span_remaining();
    reader.assert_done();
    return reader.take_ec();
}

std::size_t TLSv13NewSessionTicket::serialize(nonstd::span<uint8_t> output) const noexcept
{
    // Precompute required size for strong guarantee.
    const std::size_t need =
        4 + 4 +
        1 + ticketNonce.size() +
        2 + ticket.size() +
        extsData.size();

    if (extsData.size() < 2) return kSerializationFailed;
    if (output.size_bytes() < need) return kSerializationFailed;

    std::size_t pos = 0;

    output[pos++] = casket::get_byte<0>(ticketLifetime);
    output[pos++] = casket::get_byte<1>(ticketLifetime);
    output[pos++] = casket::get_byte<2>(ticketLifetime);
    output[pos++] = casket::get_byte<3>(ticketLifetime);

    output[pos++] = casket::get_byte<0>(ticketAgeAdd);
    output[pos++] = casket::get_byte<1>(ticketAgeAdd);
    output[pos++] = casket::get_byte<2>(ticketAgeAdd);
    output[pos++] = casket::get_byte<3>(ticketAgeAdd);

    {
        const std::size_t n = AppendLengthAndValue(
            output.subspan(pos), ticketNonce.data(), ticketNonce.size(), 1);
        if (n == kSerializationFailed) return kSerializationFailed;
        pos += n;
    }

    {
        const std::size_t n = AppendLengthAndValue(
            output.subspan(pos), ticket.data(), ticket.size(), 2);
        if (n == kSerializationFailed) return kSerializationFailed;
        pos += n;
    }

    if (!extsData.empty())
        std::memcpy(output.data() + pos, extsData.data(), extsData.size());
    pos += extsData.size();

    return pos;
}

} // namespace snet::tls