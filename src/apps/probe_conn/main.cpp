// probe_main.cpp
//
// Мини-тест probe: подключается через TlsProbeConnection к заданному
// серверу, печатает результат.
//
// Собирается вместе с твоей libsnet.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>

#include <casket/thread/pool.hpp>

#include <snet/layers/l3/ip_address.hpp>
#include <snet/proxy/tls_probe_connection.hpp>

using namespace snet;
using namespace snet::proxy;

void printResult(const TlsProbeResult& r)
{
    std::printf("\n═══ Probe result ═══\n");

    const char* statusStr = "?";
    switch (r.status)
    {
    case TlsProbeResult::Status::Ok:                statusStr = "Ok"; break;
    case TlsProbeResult::Status::ConnectFailed:     statusStr = "ConnectFailed"; break;
    case TlsProbeResult::Status::ConnectTimeout:    statusStr = "ConnectTimeout"; break;
    case TlsProbeResult::Status::HandshakeTimeout:  statusStr = "HandshakeTimeout"; break;
    case TlsProbeResult::Status::TlsError:          statusStr = "TlsError"; break;
    case TlsProbeResult::Status::NoCertificate:     statusStr = "NoCertificate"; break;
    case TlsProbeResult::Status::Cancelled:         statusStr = "Cancelled"; break;
    }
    std::printf("  Status: %s\n", statusStr);

    if (!r.error.empty())
        std::printf("  Error:  %s\n", r.error.c_str());

    std::printf("  TLS version: %s\n", r.version.toString().c_str());
    if (r.cipherSuite)
        std::printf("  Cipher: 0x%04x\n", tls::CipherSuiteGetID(r.cipherSuite));

    std::printf("  Chain length: %zu\n", r.chain.size());
    for (size_t i = 0; i < r.chain.size(); ++i)
    {
        auto& cert = r.chain[i];
        std::printf("    [%zu] %p\n", i, static_cast<const void*>(cert.get()));
        // Тут можно печатать subject/issuer, если у X509Cert есть API.
    }
    std::printf("════════════════════\n\n");
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        std::fprintf(stderr,
            "Usage: %s <server_ip> <port> [sni]\n"
            "Example: %s 10.0.1.1 8443 test.local\n",
            argv[0], argv[0]);
        return 1;
    }

    const std::string serverIpStr = argv[1];
    const uint16_t    serverPort  = static_cast<uint16_t>(std::stoi(argv[2]));
    const std::string sni         = (argc >= 4) ? argv[3] : "";

    // ── Thread pool для probe ──
    auto pool = std::make_shared<casket::thread::ThreadPool>(2);
    auto submitFn = [pool](std::function<void()> task) {
        pool->addTask(std::move(task));
    };

    // ── Probe ──
    TlsProbeConnection probe{submitFn};

    TlsProbeConnection::Config cfg;
    cfg.connectTimeout   = std::chrono::milliseconds(3000);
    cfg.handshakeTimeout = std::chrono::milliseconds(5000);

    // ── Ждём результат синхронно ──
    std::mutex              mtx;
    std::condition_variable cv;
    bool                    done = false;
    TlsProbeResult          result;

    auto serverIP = layers::IPAddress::fromString(serverIpStr.c_str());
    if (!serverIP)
    {
        std::fprintf(stderr, "invalid IP: %s\n", serverIpStr.c_str());
        return 2;
    }

    std::printf("Probing %s:%u (SNI=%s)\n",
                serverIpStr.c_str(), serverPort,
                sni.empty() ? "(none)" : sni.c_str());

    probe.asyncProbe(
        sni, serverIP.value(), serverPort, cfg,
        [&](TlsProbeResult r)
        {
            std::lock_guard lock(mtx);
            result = std::move(r);
            done   = true;
            cv.notify_one();
        });

    {
        std::unique_lock lock(mtx);
        cv.wait(lock, [&] { return done; });
    }

    printResult(result);

    return result.status == TlsProbeResult::Status::Ok ? 0 : 3;
}