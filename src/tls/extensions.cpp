#include <algorithm>
#include <iterator>

#include <snet/tls/extensions.hpp>

namespace snet::tls
{

namespace
{

/// @brief Builds a default-constructed variant alternative for @p code.
///
/// Unknown codes produce an `UnknownExtension(code)` with an empty body;
/// the body is then filled by `extensionDeserialize`.
///
/// @param[in] code Extension code.
/// @return Default-constructed alternative (known or unknown).
/// @throws std::bad_alloc if the alternative's ctor allocates.
ExtensionVariant makeDefaultExtension(ExtensionCode code)
{
    switch (code)
    {
    case ExtensionCode::ServerNameIndication:
        return ServerNameIndicator{};
    case ExtensionCode::SupportedGroups:
        return SupportedGroups{};
    case ExtensionCode::ECPointFormats:
        return SupportedPointFormats{};
    case ExtensionCode::SignatureAlgorithms:
        return SignatureAlgorithms{};
    case ExtensionCode::AppLayerProtocolNegotiation:
        return ALPN{};
    case ExtensionCode::ClientCertificateType:
        return ClientCertificateType{};
    case ExtensionCode::ServerCertificateType:
        return ServerCertificateType{};
    case ExtensionCode::EncryptThenMac:
        return EncryptThenMAC{};
    case ExtensionCode::ExtendedMasterSecret:
        return ExtendedMasterSecret{};
    case ExtensionCode::RecordSizeLimit:
        return RecordSizeLimit{};
    case ExtensionCode::SessionTicket:
        return SessionTicketExtension{};
    case ExtensionCode::SupportedVersions:
        return SupportedVersions{};
    case ExtensionCode::CertSignatureAlgorithms:
        return CertSignatureAlgorithms{};
    case ExtensionCode::PskKeyExchangeModes:
        return PskKeyExchangeModes{};
    case ExtensionCode::KeyShare:
        return KeyShare{};
    case ExtensionCode::SafeRenegotiation:
        return RenegotiationExtension{};
    default:
        return UnknownExtension(code);
    }
}

} // namespace

utils::DecodeError Extensions::deserialize(Side side, nonstd::span<const uint8_t> input,
                                           HandshakeType handshakeType) noexcept
{
    clearAll();

    utils::DataReader reader(input);

    const uint16_t allExtSize = reader.get_uint16_t();
    if (!reader.ok())
        return reader.take_error();
    if (allExtSize != reader.remaining_bytes())
    {
        return utils::DecodeError::LengthOutOfRange;
    }

    try
    {
        extensions_.reserve(allExtSize / 4);
    }
    catch (...)
    {
        return utils::DecodeError::AllocationFailed;
    }

    while (reader.has_remaining())
    {
        const auto code = static_cast<ExtensionCode>(reader.get_uint16_t());
        const uint16_t sz = reader.get_uint16_t();
        if (!reader.ok())
        {
            clearAll();
            return reader.take_error();
        }

        auto data = sz ? reader.get_span_fixed(sz) : nonstd::span<const uint8_t>{};
        if (!reader.ok())
        {
            clearAll();
            return reader.take_error();
        }

        ExtensionVariant ext;
        try
        {
            ext = makeDefaultExtension(code);
        }
        catch (...)
        {
            clearAll();
            return utils::DecodeError::AllocationFailed;
        }

        const auto err = extensionDeserialize(ext, side, data, handshakeType);
        if (err != utils::DecodeError::None)
        {
            clearAll();
            return err;
        }

        if (!add(std::move(ext)))
        {
            clearAll();
            return utils::DecodeError::LengthOutOfRange;
        }
    }

    reader.assert_done();
    return reader.take_error();
}

bool Extensions::add(ExtensionVariant ext) noexcept
{
    const auto code = extensionType(ext);
    if (find(code) != npos)
        return false;

    try
    {
        extensions_.push_back(std::move(ext));
    }
    catch (...)
    {
        return false;
    }
    mask_.insert(code);
    return true;
}

std::optional<ExtensionVariant> Extensions::take(ExtensionCode type)
{
    const auto idx = find(type);
    if (idx == npos)
        return std::nullopt;

    ExtensionVariant out = std::move(extensions_[idx]);
    extensions_.erase(extensions_.begin() + static_cast<std::ptrdiff_t>(idx));
    rebuildMask();
    return out;
}

std::set<ExtensionCode> Extensions::extensionTypes() const
{
    std::set<ExtensionCode> out;
    for (const auto& e : extensions_)
        out.insert(extensionType(e));
    return out;
}

bool Extensions::containsOtherThan(const std::set<ExtensionCode>& allowed, bool allowUnknownExtensions) const
{
    for (const auto& e : extensions_)
    {
        if (std::holds_alternative<UnknownExtension>(e))
        {
            if (allowUnknownExtensions)
                continue;
            if (!allowed.contains(extensionType(e)))
                return true;
            continue;
        }
        if (!allowed.contains(extensionType(e)))
            return true;
    }
    return false;
}

std::size_t Extensions::serialize(Side whoami, nonstd::span<uint8_t> buffer) const noexcept
{
    if (buffer.size_bytes() < 2)
        return 0;

    std::size_t total = 0;
    auto data = buffer.subspan(2);

    auto writeOne = [&](ExtensionCode code, std::size_t length) -> bool
    {
        if (length == kSerializationFailed)
            return false;
        if (data.size_bytes() < 4 + length)
            return false;

        const auto type16 = static_cast<uint16_t>(code);
        const auto len16 = static_cast<uint16_t>(length);
        data[0] = static_cast<std::uint8_t>(type16 >> 8);
        data[1] = static_cast<std::uint8_t>(type16);
        data[2] = static_cast<std::uint8_t>(len16 >> 8);
        data[3] = static_cast<std::uint8_t>(len16);

        data = data.subspan(4 + length);
        total += 4 + length;
        return true;
    };

    for (const auto& ext : extensions_)
    {
        if (extensionEmpty(ext))
            continue;
        auto body = data.subspan(data.size_bytes() >= 4 ? 4 : 0);
        const auto length = extensionSerialize(ext, whoami, body);
        if (!writeOne(extensionType(ext), length))
            return 0;
    }

    if (total > 0xFFFF)
        return 0;
    buffer[0] = static_cast<std::uint8_t>(total >> 8);
    buffer[1] = static_cast<std::uint8_t>(total);
    return total + 2;
}

void Extensions::clearAll() noexcept
{
    extensions_.clear();
    mask_.clear();
}

void Extensions::rebuildMask() noexcept
{
    mask_.clear();
    for (const auto& e : extensions_)
        mask_.insert(extensionType(e));
}

} // namespace snet::tls