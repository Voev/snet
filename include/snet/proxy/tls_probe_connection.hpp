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

/// Результат одного TLS-probe.
struct TlsProbeResult
{
    enum class Status
    {
        Ok,
        ConnectFailed,
        ConnectTimeout,
        HandshakeTimeout,
        TlsError,
        NoCertificate,
        Cancelled,
    };

    Status           status{Status::ConnectFailed};
    std::string      error;

    tls::ProtocolVersion     version;
    const tls::CipherSuite*  cipherSuite{nullptr};
    CertificateChain         chain;
};

/// Асинхронный TLS-probe.
///
/// Открывает отдельное TCP-соединение к серверу, проводит полный
/// TLS-хендшейк с указанным SNI, снимает цепочку сертификатов,
/// закрывает соединение. Оригинальный поток клиент↔прокси НЕ трогает.
///
/// Работает в фоновом потоке. Callback вызывается один раз, по
/// завершении probe, из потока пула.
///
/// Probe полностью самодостаточен: свой socket, свой RecordPool,
/// своя tls::Session. Всё умирает вместе с probe.
class TlsProbeConnection
{
public:
    struct Config
    {
        std::chrono::milliseconds connectTimeout{2000};
        std::chrono::milliseconds handshakeTimeout{3000};
        tls::ProtocolVersion      preferredVersion{tls::ProtocolVersion::TLSv1_2};
        size_t                    recordPoolSize{32};
    };

    using Callback = std::function<void(TlsProbeResult)>;
    using SubmitFn = std::function<void(std::function<void()>)>;

    explicit TlsProbeConnection(SubmitFn submit)
        : submit_(std::move(submit))
    {
    }

    /// Запустить probe асинхронно. Callback вызовется один раз.
    void asyncProbe(std::string       sni,
                    layers::IPAddress serverIP,
                    uint16_t          serverPort,
                    Config            cfg,
                    Callback          cb);

private:
    TlsProbeResult probeBlocking(std::string_view         sni,
                                 const layers::IPAddress& serverIP,
                                 uint16_t                 serverPort,
                                 const Config&            cfg);

    SubmitFn submit_;
};

} // namespace snet::proxy