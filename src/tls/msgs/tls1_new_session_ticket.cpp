#include <snet/tls/msgs/tls1_new_session_ticket.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::tls
{

void TLSv1NewSessionTicket::deserialize(nonstd::span<const uint8_t> input)
{
    utils::DataReader reader("TLSv1.2 NewSessionTicket", input);

    ticketLifetime = reader.get_uint32_t();
    ticket = reader.get_span(2, 0, 65535);

    reader.assert_done();
}

size_t TLSv1NewSessionTicket::serialize(nonstd::span<uint8_t> output) const
{
    (void)output;
    return 0;
}

} // namespace snet::tls