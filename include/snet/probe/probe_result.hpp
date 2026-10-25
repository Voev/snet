#pragma once
#include <vector>
#include <string>
#include <functional>

#include <snet/crypto/cert.hpp>
#include <snet/tls/version.hpp>
#include <snet/tls/cipher_suite.hpp>

namespace snet::probe
{

/// Ordered chain of X.509 certificates.
using CertificateChain = std::vector<snet::crypto::X509CertPtr>;

/// Result of a single TLS probe.
struct ProbeResult
{
    /// Outcome of the probe.
    enum class Status
    {
        Ok,               ///< Handshake completed; chain captured.
        ConnectFailed,    ///< TCP connection could not be established.
        ConnectTimeout,   ///< TCP connect timed out.
        HandshakeTimeout, ///< TLS handshake timed out.
        TlsError,         ///< TLS protocol/handshake error.
        NoCertificate,    ///< Server presented no certificate.
        Cancelled,        ///< Probe was cancelled.
    };

    Status status{Status::ConnectFailed}; ///< Probe outcome.
    std::string error;                    ///< Human-readable error detail (on failure).

    tls::ProtocolVersion version;                 ///< Negotiated TLS protocol version.
    const tls::CipherSuite* cipherSuite{nullptr}; ///< Negotiated cipher suite (nullptr if none).
    CertificateChain chain;                       ///< Server certificate chain captured during handshake.
};

using ProbeConnectionCallback = std::function<void(ProbeResult)>;

} // namespace snet::probe