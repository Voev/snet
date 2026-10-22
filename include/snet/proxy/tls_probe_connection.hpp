#pragma once

#include <chrono>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include <snet/layers/l3/ip_address.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/cipher_suite.hpp>
#include <snet/crypto/cert.hpp>

#include "proxy_types.hpp"

namespace snet::proxy
{

/// Result of a single TLS probe.
struct TlsProbeResult
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

/// Asynchronous TLS probe.
///
/// Opens a separate TCP connection to the server, performs a full TLS
/// handshake with the given SNI, captures the certificate chain, and
/// closes the connection. Does NOT touch the original client↔proxy stream.
///
/// Runs on a background thread. The callback is invoked exactly once,
/// on probe completion, from the pool thread.
///
/// The probe is fully self-contained: its own socket, RecordPool, and
/// tls::Session. All of it dies together with the probe.
class TlsProbeConnection
{
public:
    /// Probe tuning parameters.
    struct Config
    {
        std::chrono::milliseconds connectTimeout{2000};                       ///< TCP connect timeout.
        std::chrono::milliseconds handshakeTimeout{3000};                     ///< TLS handshake timeout.
        tls::ProtocolVersion preferredVersion{tls::ProtocolVersion::TLSv1_2}; ///< Preferred TLS version.
        size_t recordPoolSize{32}; ///< Number of records in the probe's RecordPool.
    };

    /// Completion callback invoked once with the probe result.
    using Callback = std::function<void(TlsProbeResult)>;
    /// Submits a task to the background executor.
    using SubmitFn = std::function<void(std::function<void()>)>;

    /// @param[in] submit Executor used to run probe work off the caller's thread.
    explicit TlsProbeConnection(SubmitFn submit)
        : submit_(std::move(submit))
    {
    }

    /// Start an asynchronous probe.
    ///
    /// @param[in] sni        SNI to present during the handshake.
    /// @param[in] serverIP   Upstream server address.
    /// @param[in] serverPort Upstream server port.
    /// @param[in] cfg        Probe tuning parameters.
    /// @param[in] cb         Callback invoked once on completion.
    void asyncProbe(std::string sni, layers::IPAddress serverIP, uint16_t serverPort, Config cfg, Callback cb);

private:
    /// Run the probe synchronously on the current thread.
    ///
    /// @param[in] sni        SNI to present during the handshake.
    /// @param[in] serverIP   Upstream server address.
    /// @param[in] serverPort Upstream server port.
    /// @param[in] cfg        Probe tuning parameters.
    /// @return Probe result (chain on success, error status otherwise).
    TlsProbeResult probeBlocking(std::string_view sni, const layers::IPAddress& serverIP, uint16_t serverPort,
                                 const Config& cfg);

    SubmitFn submit_; ///< Executor for background probe work.
};

} // namespace snet::proxy