#include <snet/tls/msg/certificate.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::tls::msg
{

void Certificate::deserialize(std::span<const uint8_t> buffer)
{
    utils::DataReader reader("Certificate", buffer);

    const size_t certsLength = reader.get_uint24_t();
    ::utils::ThrowIfTrue(reader.remaining_bytes() != certsLength, "Certificate: Message malformed");

    while (reader.has_remaining())
    {
        CertEntry entry;
        entry.certificate = reader.get_tls_length_value(3);
        certEntries.push_back(entry);
    }

    reader.assert_done();
}

size_t Certificate::serialize(std::span<uint8_t> buffer) const
{
    (void)buffer;
    return 0;
}

} // namespace snet::tls::msg