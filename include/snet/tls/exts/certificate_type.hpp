#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <casket/nonstd/span.hpp>

#include <snet/tls/exts/extension_code.hpp>
#include <snet/tls/types.hpp>
#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

/// Certificate types as defined in RFC 7250 / RFC 8446 4.4.2.
///
/// Note: the wire field is a single byte; values 0 and 2 are currently
/// registered (X.509 and RawPublicKey). Other values are syntactically valid
/// but unsupported — the caller decides whether to reject them.
enum class CertificateType : uint8_t
{
    X509 = 0,         ///< X.509 certificate.
    RawPublicKey = 2, ///< Raw public key.
};

/// Human-readable name. `constexpr noexcept`, no allocation.
constexpr const char* toString(CertificateType t) noexcept
{
    switch (t)
    {
    case CertificateType::X509:
        return "X509";
    case CertificateType::RawPublicKey:
        return "RawPublicKey";
    }
    return "Unknown";
}

/// Parses a name produced by `toString`. Throws on unknown input
/// (this is a config-level API, not hot path).
CertificateType certificateTypeFromString(const std::string& s);

// ---------------------------------------------------------------------------
// Shared parsing / serialization helpers (no virtual, no throw)
// ---------------------------------------------------------------------------

namespace detail
{

/// Parses the wire form of client/server certificate_type extension into `out`.
///   * Client side: <1-byte length> <type byte>*  (RFC 7250 4.1)
///   * Server side: <1-byte type>                 (RFC 7250 4.2)
/// Returns DecodeError::None on success. Never throws.
utils::DecodeError parseCertificateTypes(Side side, nonstd::span<const uint8_t> input,
                                         std::vector<CertificateType>& out) noexcept;

/// Serializes `types` according to `side`.
/// Returns bytes written, or 0 on buffer-too-small / bad size.
std::size_t serializeCertificateTypes(Side side, nonstd::span<const CertificateType> types,
                                      nonstd::span<uint8_t> output) noexcept;

} // namespace detail

// ---------------------------------------------------------------------------
// ClientCertificateType (RFC 7250 4.1)
// ---------------------------------------------------------------------------

class ClientCertificateType final
{
public:
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::ClientCertificateType;
    }

    ClientCertificateType() noexcept = default;

    /// Advertise support for the given certificate types (client side).
    explicit ClientCertificateType(std::vector<CertificateType> types)
        : certTypes_(std::move(types))
    {
    }

    /// Server-side selection from client's preferences.
    /// Picks the first of `serverPreference` that the client offered.
    /// If none match, the result is empty and `empty()` returns true.
    ClientCertificateType(const ClientCertificateType& fromClient,
                          nonstd::span<const CertificateType> serverPreference);

    bool empty() const noexcept
    {
        // RFC 7250 4.1: omit the extension if only X.509 is offered.
        return certTypes_.size() == 1 && certTypes_.front() == CertificateType::X509;
    }

    std::size_t serialize(Side side, nonstd::span<uint8_t> output) const noexcept
    {
        return detail::serializeCertificateTypes(side, certTypes_, output);
    }

    utils::DecodeError deserialize(Side side, nonstd::span<const uint8_t> input) noexcept
    {
        certTypes_.clear();
        return detail::parseCertificateTypes(side, input, certTypes_);
    }

    nonstd::span<const CertificateType> types() const noexcept
    {
        return {certTypes_.data(), certTypes_.size()};
    }

    /// The single negotiated type (server side). Precondition: `!empty()`.
    CertificateType selectedCertificateType() const noexcept
    {
        return certTypes_.empty() ? CertificateType::X509 : certTypes_.front();
    }

    /// Checks that the server's selection is among the client's offers.
    /// Returns DecodeError::LengthOutOfRange if not.
    utils::DecodeError validateSelection(const ClientCertificateType& fromServer) const noexcept;

private:
    std::vector<CertificateType> certTypes_;
};

// ---------------------------------------------------------------------------
// ServerCertificateType (RFC 7250 4.2)
// ---------------------------------------------------------------------------

class ServerCertificateType final
{
public:
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::ServerCertificateType;
    }

    ServerCertificateType() noexcept = default;

    explicit ServerCertificateType(std::vector<CertificateType> types)
        : certTypes_(std::move(types))
    {
    }

    ServerCertificateType(const ServerCertificateType& fromClient,
                          nonstd::span<const CertificateType> serverPreference);

    bool empty() const noexcept
    {
        return certTypes_.size() == 1 && certTypes_.front() == CertificateType::X509;
    }

    std::size_t serialize(Side side, nonstd::span<uint8_t> output) const noexcept
    {
        return detail::serializeCertificateTypes(side, certTypes_, output);
    }

    utils::DecodeError deserialize(Side side, nonstd::span<const uint8_t> input) noexcept
    {
        certTypes_.clear();
        return detail::parseCertificateTypes(side, input, certTypes_);
    }

    nonstd::span<const CertificateType> types() const noexcept
    {
        return {certTypes_.data(), certTypes_.size()};
    }

    CertificateType selectedCertificateType() const noexcept
    {
        return certTypes_.empty() ? CertificateType::X509 : certTypes_.front();
    }

    utils::DecodeError validateSelection(const ServerCertificateType& fromServer) const noexcept;

private:
    std::vector<CertificateType> certTypes_;
};

} // namespace snet::tls