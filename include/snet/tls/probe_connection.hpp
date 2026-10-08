#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include <snet/layers/l3/ip_address.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/cipher_suite.hpp>
#include <snet/crypto/cert.hpp>

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

    Status      status{Status::ConnectFailed};
    std::string error;

    // Параметры согласованного TLS.
    tls::ProtocolVersion    version;
    const tls::CipherSuite* cipherSuite{nullptr};

    // Цепочка сертификатов сервера, leaf первым.
    std::vector<crypto::X509CertPtr> chain;
};

/// Асинхронный TLS-probe.
///
/// Открывает TCP к `serverIP:serverPort`, проводит минимальный
/// TLS-хендшейк с указанным SNI, снимает сертификат сервера,
/// закрывает соединение. Состояние не течёт наружу — вся возня
/// (сокет, Session, RecordPool) умирает вместе с probe.
///
/// Всё делается в фоновом потоке. Callback вызывается один раз,
/// по завершении probe, из потока пула.
class TlsProbeConnection
{
public:
    struct Config
    {
        std::chrono::milliseconds connectTimeout{2000};
        std::chrono::milliseconds handshakeTimeout{3000};

        /// Какую версию TLS просить. По умолчанию — 1.3.
        /// Для TLS 1.3 сертификат приходит зашифрованным, но Session
        /// деривит handshake-ключи и расшифровывает.
        tls::ProtocolVersion preferredVersion{tls::ProtocolVersion::TLSv1_3};

        /// Размер пула записей. 32 хватает с запасом для одного probe.
        size_t recordPoolSize{32};
    };

    using Callback = std::function<void(TlsProbeResult)>;

    /// Submit-fn — абстракция над пулом потоков / asio / чем угодно.
    /// Принимает задачу и запускает её в фоне.
    using SubmitFn = std::function<void(std::function<void()>)>;

    explicit TlsProbeConnection(SubmitFn submit)
        : submit_(std::move(submit))
    {
    }

    /// Запустить probe. Callback сработает один раз, асинхронно.
    void asyncProbe(std::string        sni,
                    layers::IPAddress  serverIP,
                    uint16_t           serverPort,
                    Config             cfg,
                    Callback           cb);

private:
    TlsProbeResult probeBlocking(std::string_view          sni,
                                 const layers::IPAddress&  serverIP,
                                 uint16_t                  serverPort,
                                 const Config&             cfg);

    SubmitFn submit_;
};

} // namespace snet::proxy