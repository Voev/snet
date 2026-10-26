#include <algorithm>
#include <iterator>

#include <snet/tls/extensions.hpp>

namespace snet::tls {

namespace {

/// @brief Checks whether @p code is handled by `ExtensionVariant`
///        (i.e. has a dedicated alternative in `makeDefaultExtension`).
bool isKnownCode(ExtensionCode code) noexcept {
    switch (code) {
    case ExtensionCode::ServerNameIndication:
    case ExtensionCode::SupportedGroups:
    case ExtensionCode::ECPointFormats:
    case ExtensionCode::SignatureAlgorithms:
    case ExtensionCode::AppLayerProtocolNegotiation:
    case ExtensionCode::ClientCertificateType:
    case ExtensionCode::ServerCertificateType:
    case ExtensionCode::EncryptThenMac:
    case ExtensionCode::ExtendedMasterSecret:
    case ExtensionCode::RecordSizeLimit:
    case ExtensionCode::SessionTicket:
    case ExtensionCode::SupportedVersions:
    case ExtensionCode::CertSignatureAlgorithms:
    case ExtensionCode::PskKeyExchangeModes:
    case ExtensionCode::KeyShare:
        return true;
    default:
        return false;
    }
}

/// @brief Builds a default-constructed variant alternative for @p code.
///        Precondition: `isKnownCode(code) == true`.
/// @throws std::bad_alloc if the alternative's ctor allocates.
ExtensionVariant makeDefaultExtension(ExtensionCode code) {
    switch (code) {
    case ExtensionCode::ServerNameIndication:        return ServerNameIndicator{};
    case ExtensionCode::SupportedGroups:             return SupportedGroups{};
    case ExtensionCode::ECPointFormats:              return SupportedPointFormats{};
    case ExtensionCode::SignatureAlgorithms:         return SignatureAlgorithms{};
    case ExtensionCode::AppLayerProtocolNegotiation: return ALPN{};
    case ExtensionCode::ClientCertificateType:       return ClientCertificateType{};
    case ExtensionCode::ServerCertificateType:       return ServerCertificateType{};
    case ExtensionCode::EncryptThenMac:              return EncryptThenMAC{};
    case ExtensionCode::ExtendedMasterSecret:        return ExtendedMasterSecret{};
    case ExtensionCode::RecordSizeLimit:             return RecordSizeLimit{};
    case ExtensionCode::SessionTicket:               return SessionTicketExtension{};
    case ExtensionCode::SupportedVersions:           return SupportedVersions{};
    case ExtensionCode::CertSignatureAlgorithms:     return CertSignatureAlgorithms{};
    case ExtensionCode::PskKeyExchangeModes:         return PskKeyExchangeModes{};
    case ExtensionCode::KeyShare:                    return KeyShare{};
    default:                                         return ServerNameIndicator{}; // unreachable
    }
}

} // namespace

// ---------------------------------------------------------------------------
// deserialize
// ---------------------------------------------------------------------------

utils::DecodeError Extensions::deserialize(Side side,
                                           nonstd::span<const uint8_t> input,
                                           HandshakeType handshakeType) noexcept {
    // Reset on every call: object may be reused across handshakes.
    extensions_.clear();
    unknown_.clear();
    mask_.clear();

    utils::DataReader reader("Extensions", input);

    const uint16_t allExtSize = reader.get_uint16_t();
    if (!reader.ok()) return reader.take_error();
    if (allExtSize != reader.remaining_bytes()) {
        return utils::DecodeError::LengthOutOfRange;
    }

    // Upper bound on entry count: every extension has >= 4 bytes header.
    try {
        extensions_.reserve(allExtSize / 4);
    } catch (...) {
        return utils::DecodeError::AllocationFailed;
    }

    while (reader.has_remaining()) {
        const auto code = static_cast<ExtensionCode>(reader.get_uint16_t());
        const uint16_t sz = reader.get_uint16_t();
        if (!reader.ok()) { clearAll(); return reader.take_error(); }

        auto data = sz ? reader.get_span_fixed(sz) : nonstd::span<const uint8_t>{};
        if (!reader.ok()) { clearAll(); return reader.take_error(); }

        if (isKnownCode(code)) {
            // Known code: parse into a variant alternative.
            ExtensionVariant ext;
            try {
                ext = makeDefaultExtension(code);
            } catch (...) {
                clearAll();
                return utils::DecodeError::AllocationFailed;
            }

            const auto err = extensionDeserialize(ext, side, data, handshakeType);
            if (err != utils::DecodeError::None) { clearAll(); return err; }

            if (!add(std::move(ext))) {
                clearAll();
                return utils::DecodeError::LengthOutOfRange;   // duplicate code
            }
        } else {
            // Unknown code: keep the raw bytes verbatim.
            UnknownExtension u(code, {});
            const auto err = u.deserialize(side, data);
            if (err != utils::DecodeError::None) { clearAll(); return err; }

            if (!addUnknown(std::move(u))) {
                clearAll();
                return utils::DecodeError::LengthOutOfRange;
            }
        }
    }

    reader.assert_done();
    return reader.take_error();
}

// ---------------------------------------------------------------------------
// add / addUnknown
// ---------------------------------------------------------------------------

bool Extensions::add(ExtensionVariant ext) noexcept {
    const auto code = extensionType(ext);
    if (mask_.contains(code) || findUnknown(code) != npos) return false;

    try {
        extensions_.push_back(std::move(ext));
    } catch (...) {
        return false;
    }
    mask_.insert(code);
    return true;
}

bool Extensions::addUnknown(UnknownExtension ext) noexcept {
    const auto code = ext.type();
    if (mask_.contains(code) || findUnknown(code) != npos) return false;

    try {
        unknown_.push_back(std::move(ext));
    } catch (...) {
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// take
// ---------------------------------------------------------------------------

std::optional<ExtensionVariant> Extensions::take(ExtensionCode type) {
    if (auto idx = find(type); idx != npos) {
        ExtensionVariant out = std::move(extensions_[idx]);
        extensions_.erase(extensions_.begin() + static_cast<std::ptrdiff_t>(idx));
        rebuildMask();
        return out;
    }

    if (auto idx = findUnknown(type); idx != npos) {
        // Materialize an UnknownExtension back into a variant? No: variant has
        // no UnknownExtension alternative. Return nullopt; caller should use
        // takeUnknown for unknown codes.
        (void)idx;
    }
    return std::nullopt;
}

std::optional<UnknownExtension> Extensions::takeUnknown(ExtensionCode type) {
    const auto idx = findUnknown(type);
    if (idx == npos) return std::nullopt;

    UnknownExtension out = std::move(unknown_[idx]);
    unknown_.erase(unknown_.begin() + static_cast<std::ptrdiff_t>(idx));
    return out;
}

// ---------------------------------------------------------------------------
// extensionTypes / containsOtherThan
// ---------------------------------------------------------------------------

std::set<ExtensionCode> Extensions::extensionTypes() const {
    std::set<ExtensionCode> out;
    for (const auto& e : extensions_) out.insert(extensionType(e));
    for (const auto& u : unknown_)    out.insert(u.type());
    return out;
}

bool Extensions::containsOtherThan(const std::set<ExtensionCode>& allowed,
                                   bool allowUnknownExtensions) const {
    for (const auto& e : extensions_) {
        const auto code = extensionType(e);
        if (!allowed.contains(code)) return true;
    }

    if (!allowUnknownExtensions) {
        for (const auto& u : unknown_) {
            if (!allowed.contains(u.type())) return true;
        }
    } else {
        // Unknown codes are tolerated; known codes not in `allowed` already
        // caught by the loop above.
    }
    return false;
}

// ---------------------------------------------------------------------------
// serialize
// ---------------------------------------------------------------------------

std::size_t Extensions::serialize(Side whoami,
                                  nonstd::span<uint8_t> buffer) const noexcept {
    if (buffer.size_bytes() < 2) return 0;

    std::size_t total = 0;
    auto data = buffer.subspan(2);

    auto writeOne = [&](ExtensionCode code, std::size_t length,
                        nonstd::span<uint8_t> body) -> bool {
        if (length == kSerializationFailed) return false;
        if (data.size_bytes() < 4 + length) return false;

        const auto type16 = static_cast<uint16_t>(code);
        const auto len16  = static_cast<uint16_t>(length);
        data[0] = static_cast<std::uint8_t>(type16 >> 8);
        data[1] = static_cast<std::uint8_t>(type16);
        data[2] = static_cast<std::uint8_t>(len16 >> 8);
        data[3] = static_cast<std::uint8_t>(len16);

        (void)body;
        data = data.subspan(4 + length);
        total += 4 + length;
        return true;
    };

    for (const auto& ext : extensions_) {
        if (extensionEmpty(ext)) continue;
        auto body = data.subspan(data.size_bytes() >= 4 ? 4 : 0);
        const auto length = extensionSerialize(ext, whoami, body);
        if (!writeOne(extensionType(ext), length, body)) return 0;
    }

    for (const auto& u : unknown_) {
        auto body = data.subspan(data.size_bytes() >= 4 ? 4 : 0);
        const auto length = u.serialize(whoami, body);
        if (!writeOne(u.type(), length, body)) return 0;
    }

    if (total > 0xFFFF) return 0;
    buffer[0] = static_cast<std::uint8_t>(total >> 8);
    buffer[1] = static_cast<std::uint8_t>(total);
    return total + 2;
}

// ---------------------------------------------------------------------------
// private helpers
// ---------------------------------------------------------------------------

void Extensions::clearAll() noexcept {
    extensions_.clear();
    unknown_.clear();
    mask_.clear();
}

void Extensions::rebuildMask() noexcept {
    mask_.clear();
    for (const auto& e : extensions_) mask_.insert(extensionType(e));
}

} // namespace snet::tls