/// @file
/// @brief Concrete Policy implementation for a probe ClientHello.

#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include <casket/nonstd/span.hpp>

#include <snet/crypto/group_params.hpp>
#include <snet/tls/cipher_suite_manager.hpp>
#include <snet/tls/policy.hpp>
#include <snet/tls/version.hpp>

namespace snet::probe
{

/// @brief Policy for a probe ClientHello.
///
/// All data is pulled from static/cached sources (CipherSuiteManager,
/// crypto backend); the policy itself only holds a reference to the SNI
/// and a single preferred version. Cheap to construct; must not outlive
/// constructClientHello().
///
/// The policy advertises:
///   - our preferred version only (single entry);
///   - all cipher suites currently supported by CipherSuiteManager;
///   - all groups supported by the crypto backend;
///   - a conservative default set of signature algorithms;
///   - no session ticket, no ALPN, no session resumption.
class ProbeClientHelloPolicy final : public tls::Policy
{
public:
    /// @param[in] preferredVersion Version to advertise as preferred.
    /// @param[in] sni              SNI to send.
    ProbeClientHelloPolicy(tls::ProtocolVersion preferredVersion, nonstd::string_view sni) noexcept
        : preferredVersion_(preferredVersion)
        , sni_(sni)
    {
        // Supported cipher suites: view into CipherSuiteManager's cache.
        cipherSuites_ = tls::CipherSuiteManager::getInstance().getSupportedCipherSuites();

        // Supported groups: view into crypto backend's static list.
        groupParams_ = crypto::GroupParams::getSupported();

        // A conservative default set of signature algorithms.
        // Covers TLS 1.2 (RSA-PKCS1, ECDSA) and TLS 1.3 (RSA-PSS, EdDSA).
        static constexpr std::uint16_t kDefaultSigAlgs[] = {
            0x0403, // ecdsa_secp256r1_sha256
            0x0503, // ecdsa_secp384r1_sha384
            0x0603, // ecdsa_secp521r1_sha512
            0x0804, // rsa_pss_rsae_sha256
            0x0805, // rsa_pss_rsae_sha384
            0x0806, // rsa_pss_rsae_sha512
            0x0807, // ed25519
            0x0808, // ed448
            0x0809, // rsa_pss_pss_sha256
            0x080A, // rsa_pss_pss_sha384
            0x080B, // rsa_pss_pss_sha512
            0x0401, // rsa_pkcs1_sha256
            0x0501, // rsa_pkcs1_sha384
            0x0601, // rsa_pkcs1_sha512
        };
        signatureAlgorithms_.assign(std::begin(kDefaultSigAlgs), std::end(kDefaultSigAlgs));
    }

    nonstd::string_view serverNameIndication() const noexcept override
    {
        return sni_;
    }

    nonstd::span<const tls::ProtocolVersion> supportedVersion() const noexcept override
    {
        return {&preferredVersion_, 1};
    }

    nonstd::span<const tls::CipherSuite*> offeredCipherSuites() const noexcept override
    {
        return cipherSuites_;
    }

    nonstd::span<const crypto::GroupParams> offeredGroupParams() const noexcept override
    {
        return groupParams_;
    }

    nonstd::span<std::uint8_t> clientSessionId() const noexcept override
    {
        return {}; // no resumption for probe
    }

    nonstd::span<nonstd::string_view> alpnProtocols() const noexcept override
    {
        return {};
    }

    nonstd::span<std::uint16_t> signatureAlgorithms() const noexcept override
    {
        return {signatureAlgorithms_.data(), signatureAlgorithms_.size()};
    }

    bool useEncryptThenMac() const noexcept override
    {
        return false;
    }
    bool useExtendedMasterSecret() const noexcept override
    {
        return true;
    }
    bool useSessionTicket() const noexcept override
    {
        return false;
    }
    bool useRenegotiationInfo() const noexcept override
    {
        return true;
    }

private:
    tls::ProtocolVersion preferredVersion_;
    nonstd::string_view sni_;

    nonstd::span<const tls::CipherSuite*> cipherSuites_;
    nonstd::span<const crypto::GroupParams> groupParams_;
    std::vector<std::uint16_t> signatureAlgorithms_;
};

} // namespace snet::probe