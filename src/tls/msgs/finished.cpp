#include <snet/crypto/exception.hpp>

#include <snet/tls/msgs/finished.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

#include <casket/utils/exception.hpp>

namespace snet::tls
{

void Finished::deserialize(const ProtocolVersion& version, nonstd::span<const uint8_t> input)
{
    (void)version;
    verifyData_.assign(input.begin(), input.end());
}

size_t Finished::serialize(const ProtocolVersion& version, nonstd::span<uint8_t> output) const
{
    (void)version;
    (void)output;

    return 0;
}

} // namespace snet::tls