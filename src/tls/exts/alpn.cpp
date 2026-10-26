#include <snet/tls/exts/alpn.hpp>

#include <stdexcept>

namespace snet::tls
{

ALPN::ALPN(const std::vector<std::string>& protocols)
{
    buf_.reserve(protocols.size() * 8);
    offsets_.reserve(protocols.size());
    for (const auto& p : protocols)
    {
        if (p.empty() || p.size() > 255)
        {
            clear();
            throw std::invalid_argument("ALPN protocol name must be 1..255 bytes");
        }
        if (!appendProtocol(p))
        {
            clear();
            throw std::bad_alloc();
        }
    }
}

bool ALPN::appendProtocol(nonstd::string_view p) noexcept
{
    const std::size_t len = p.size();
    if (len == 0 || len > 255)
        return false;
    try
    {
        offsets_.push_back(static_cast<std::uint16_t>(buf_.size()));
        buf_.push_back(static_cast<char>(len));
        buf_.insert(buf_.end(), p.data(), p.data() + len);
        return true;
    }
    catch (...)
    {
        // Leave the object consistent on OOM.
        buf_.clear();
        offsets_.clear();
        return false;
    }
}

utils::DecodeError ALPN::deserialize(Side side, nonstd::span<const uint8_t> input) noexcept
{
    clear();

    utils::DataReader reader("ALPN", input);

    const std::uint16_t nameBytes = reader.get_uint16_t();
    if (!reader.ok())
        return reader.take_error();
    if (nameBytes != reader.remaining_bytes())
        return utils::DecodeError::LengthOutOfRange;

    try
    {
        offsets_.reserve(nameBytes / 2);
        buf_.reserve(nameBytes);
    }
    catch (...)
    {
        return utils::DecodeError::AllocationFailed;
    }

    while (reader.has_remaining())
    {
        const auto p = reader.get_string_view(1, 1, 255);
        if (!reader.ok())
        {
            clear();
            return reader.take_error();
        }

        if (!appendProtocol(p))
        {
            clear();
            return utils::DecodeError::AllocationFailed;
        }
    }
    reader.assert_done();
    if (!reader.ok())
    {
        clear();
        return reader.take_error();
    }

    // RFC 7301 §3.1: server response MUST contain exactly one protocol.
    if (side == Side::Server && offsets_.size() != 1)
    {
        clear();
        return utils::DecodeError::LengthOutOfRange;
    }
    return utils::DecodeError::None;
}

} // namespace snet::tls