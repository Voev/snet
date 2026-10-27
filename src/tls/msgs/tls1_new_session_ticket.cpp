#include <snet/tls/msgs/tls1_new_session_ticket.hpp>

#include <cstring>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>
#include <snet/utils/decode_error.hpp>
#include <casket/utils/load_store.hpp>

namespace snet::tls
{

using snet::AppendLengthAndValue;
using snet::kSerializationFailed;

std::error_code TLSv1NewSessionTicket::deserialize(nonstd::span<const uint8_t> input) noexcept
{
    ticketLifetime = 0;
    ticket = {};

    utils::DataReader reader(input);

    ticketLifetime = reader.get_uint32_t();
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    ticket = reader.get_span_length_and_value(2);
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    reader.assert_done();
    return reader.take_ec();
}

std::size_t TLSv1NewSessionTicket::serialize(nonstd::span<uint8_t> output) const noexcept
{
    const std::size_t need = 4 + 2 + ticket.size();
    if (output.size_bytes() < need)
        return kSerializationFailed;

    std::size_t pos = 0;

    output[pos++] = casket::get_byte<0>(ticketLifetime);
    output[pos++] = casket::get_byte<1>(ticketLifetime);
    output[pos++] = casket::get_byte<2>(ticketLifetime);
    output[pos++] = casket::get_byte<3>(ticketLifetime);

    const std::size_t n = AppendLengthAndValue(output.subspan(pos), ticket.data(), ticket.size(), 2);
    if (n == kSerializationFailed)
        return kSerializationFailed;

    return pos + n;
}

} // namespace snet::tls