#include <snet/tls/msgs/tls13_new_session_ticket.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::tls
{

void TLSv13NewSessionTicket::deserialize(nonstd::span<const uint8_t> input)
{
    utils::DataReader reader("TLSv1.3 NewSessionTicket", input);

    ticketLifetime = reader.get_uint32_t();
    ticketAgeAdd = reader.get_uint32_t();
    ticketNonce = reader.get_span_length_and_value(1);
    ticket = reader.get_span_length_and_value(2);

    const auto extsLength = reader.peek_uint16_t();
    casket::ThrowIfFalse(extsLength != reader.remaining_bytes(), "Invalid extensions length");
    extsData = reader.get_span_fixed(2 + extsLength);

    reader.assert_done();
}

size_t TLSv13NewSessionTicket::serialize(nonstd::span<uint8_t> output) const
{
    (void)output;
    return 0;
}

} // namespace snet::tls