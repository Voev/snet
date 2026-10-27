#include <snet/tls/msgs/server_hello.hpp>
#include <snet/tls/session.hpp>

#include <algorithm>
#include <cstring>

#include <snet/tls/exts/extension_code.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/decode_error.hpp>

using namespace snet::utils;

namespace snet::tls
{

namespace
{

/// @brief SHA-256("HelloRetryRequest"), used as the special `random` value
///        in a TLS 1.3 HelloRetryRequest (RFC 8446 §4.1.3).
constexpr std::array<std::uint8_t, TLS_RANDOM_SIZE> kHelloRetryRequestMarker = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

inline bool isHelloRetryRequestRandom(nonstd::span<const std::uint8_t> r) noexcept
{
    return r.size() == TLS_RANDOM_SIZE &&
           std::equal(kHelloRetryRequestMarker.begin(), kHelloRetryRequestMarker.end(), r.begin());
}

} // namespace

std::error_code ServerHello::deserialize(nonstd::span<const uint8_t> input) noexcept
{
    version = {};
    random = {};
    sessionID = {};
    cipherSuite = 0;
    compMethod = 0;
    extensions = {};
    isHelloRetryRequest = false;

    utils::DataReader reader(input);

    version = ProtocolVersion(reader.get_uint16_t());
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    random = reader.get_span_fixed(TLS_RANDOM_SIZE);
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    isHelloRetryRequest = isHelloRetryRequestRandom(random);

    sessionID = reader.get_span(1, 0, 32);
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    cipherSuite = reader.get_uint16_t();
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    compMethod = reader.get_byte();
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    if (reader.remaining_bytes() > 0)
    {
        const auto extensionsLength = reader.peek_uint16_t();
        if (!reader.ok())
        {
            return reader.take_ec();
        }
        if (extensionsLength != reader.remaining_bytes() - 2)
        {
            return make_error_code(DecodeError::LengthOutOfRange);
        }
        extensions = reader.get_span_fixed(2 + extensionsLength);
        if (!reader.ok())
        {
            return reader.take_ec();
        }
    }

    reader.assert_done();
    return reader.take_ec();
}

std::size_t ServerHello::serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept
{
    const std::size_t fixed = 2 + TLS_RANDOM_SIZE + 1 + sessionID.size() + 2 + 1; // cipherSuite + compMethod

    if (output.size_bytes() < fixed)
    {
        return kSerializationFailed;
    }

    std::size_t pos = 0;

    output[pos++] = version.majorVersion();
    output[pos++] = version.minorVersion();

    std::memcpy(output.data() + pos, random.data(), TLS_RANDOM_SIZE);
    pos += TLS_RANDOM_SIZE;

    if (sessionID.size() > 255)
    {
        return kSerializationFailed;
    }

    output[pos++] = static_cast<std::uint8_t>(sessionID.size());

    if (!sessionID.empty())
    {
        std::memcpy(output.data() + pos, sessionID.data(), sessionID.size());
    }
    pos += sessionID.size();

    output[pos++] = casket::get_byte<0>(cipherSuite);
    output[pos++] = casket::get_byte<1>(cipherSuite);
    output[pos++] = compMethod;

    const auto extWritten = session.getServerExtensions().serialize(Side::Server, output.subspan(pos));
    if (extWritten == 0)
    {
        return kSerializationFailed;
    }

    return pos + extWritten;
}

} // namespace snet::tls