#include <snet/proxy/tls_probe_connection.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/rand.h>
#include <snet/tls/session.hpp>
#include <snet/tls/record_pool.hpp>
#include <snet/tls/record.hpp>
#include <snet/tls/msgs/handshake_message.hpp>
#include <snet/tls/extensions.hpp>
#include <snet/tls/record_printer.hpp>

#include <casket/log/log.hpp>


using namespace snet;
using namespace snet::tls;

namespace snet::proxy
{

namespace
{

/// RAII над файловым дескриптором сокета.
class ScopedFd
{
public:
    ScopedFd() = default;
    explicit ScopedFd(int fd) : fd_(fd) {}
    ~ScopedFd() { reset(); }

    ScopedFd(const ScopedFd&)            = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;

    ScopedFd(ScopedFd&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    ScopedFd& operator=(ScopedFd&& o) noexcept
    {
        if (this != &o) { reset(); fd_ = o.fd_; o.fd_ = -1; }
        return *this;
    }

    void reset(int fd = -1) noexcept { if (fd_ >= 0) ::close(fd_); fd_ = fd; }
    [[nodiscard]] int  get()   const noexcept { return fd_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }

private:
    int fd_{-1};
};

sockaddr_in toSockaddr(const snet::layers::IPAddress& ip, uint16_t port)
{
    sockaddr_in sa{};
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(port);
    sa.sin_addr.s_addr = ip.toIPv4().toNetwork();
    return sa;
}

int pollOne(int fd, short events, std::chrono::milliseconds timeout)
{
    pollfd pfd{};
    pfd.fd     = fd;
    pfd.events = events;

    const int rc = ::poll(&pfd, 1, static_cast<int>(timeout.count()));
    if (rc < 0) return -1;
    if (rc == 0) return 0;
    return pfd.revents;
}

bool connectWithTimeout(int fd, const sockaddr_in& sa,
                        std::chrono::milliseconds timeout)
{
    const int rc = ::connect(fd,
                             reinterpret_cast<const sockaddr*>(&sa),
                             sizeof(sa));
    if (rc == 0) return true;
    if (errno != EINPROGRESS) return false;

    const int ev = pollOne(fd, POLLOUT, timeout);
    if (ev <= 0) return false;

    int err = 0;
    socklen_t len = sizeof(err);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
        return false;

    return err == 0;
}

bool sendAll(int fd, const uint8_t* data, size_t len)
{
    size_t sent = 0;
    while (sent < len)
    {
        const ssize_t n = ::send(fd, data + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0)
        {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                if (pollOne(fd, POLLOUT, std::chrono::milliseconds{500}) <= 0)
                    return false;
                continue;
            }
            return false;
        }
        if (n == 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

/// Сериализует список расширений в wire-format.
///
/// wire format:
///   uint16 total_length
///   [
///     uint16 type
///     uint16 length
///     uint8  data[length]
///   ]...
std::vector<uint8_t> buildExtensionsBlob(std::string_view sni);

std::vector<uint8_t> buildClientHelloRecord(std::string_view sni,
                                            tls::ProtocolVersion preferred,
                                            tls::RecordPool& pool,
                                            tls::Session& session)
{
    // 1. Сырой блоб расширений в формате [type:2][len:2][body]...
    //    Именно его парсит constructClientHello.
    auto extensionsBlob = buildExtensionsBlob(sni);
    if (extensionsBlob.empty())
        return {};

    // 2. Cipher suites и compression methods — constructClientHello
    //    их НЕ заполняет, поэтому делаем это сами.
    static const std::array<uint8_t, 14> suites = {
        0x13, 0x01,  // TLS_AES_128_GCM_SHA256
        0x13, 0x02,  // TLS_AES_256_GCM_SHA384
        0x13, 0x03,  // TLS_CHACHA20_POLY1305_SHA256
        0xC0, 0x2F,  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC0, 0x30,  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0x00, 0x9E,  // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        0x00, 0x9F,  // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    };
    static const std::array<uint8_t, 1> compMethods = { 0x00 };

    // 3. ClientHello. random заполнит constructClientHello.
    tls::ClientHello ch{};
    ch.version     = preferred;
    ch.random      = {};                                 // заполнится внутри
    ch.sessionID   = {};
    ch.suites      = { suites.data(), suites.size() };
    ch.compMethods = { compMethods.data(), compMethods.size() };
    ch.extensions  = { extensionsBlob.data(), extensionsBlob.size() };

    // 4. Настраиваем сессию и наполняем clientExtensions_
    //    через парсинг ch.extensions. Заодно генерируется random
    //    и эфемерный ключ для KeyShare.
    session.setVersion(preferred);
    session.constructClientHello(ch);

    // 5. Запись из пула.
    auto* rec = pool.acquire();
    if (!rec)
        return {};

    // 6. Сериализация. Все span'ы в ch указывают на локальные буферы,
    //    которые живы до конца функции — это безопасно, потому что
    //    serializeHandshake пишет байты сразу.
    if (!rec->serializeHandshake(
            tls::HandshakeMessage(std::move(ch), tls::HandshakeType::ClientHelloCode),
            0, session))
    {
        pool.release(rec);
        return {};
    }

    session.addOutgoingRecord(0, rec);

    // 7. Динамический буфер вывода.
    std::vector<uint8_t> out(4096);
    const size_t n = session.writeRecords({ out.data(), out.size() });
    if (n == 0)
        return {};
    out.resize(n);
    return out;
}

CertificateChain extractChain(const tls::Certificate& certMsg)
{
    CertificateChain out;

    auto collect = [&out](const auto& entries)
    {
        out.reserve(entries.size());
        for (const auto& e : entries)
        {
            if (auto cert = crypto::Cert::fromBuffer(e.certData))
                out.push_back(std::move(cert));
        }
    };

    if (std::holds_alternative<tls::TLSv13Certificate>(certMsg.message))
        collect(std::get<tls::TLSv13Certificate>(certMsg.message).entryList);
    else if (std::holds_alternative<tls::TLSv1Certificate>(certMsg.message))
        collect(std::get<tls::TLSv1Certificate>(certMsg.message).entryList);

    return out;
}

std::vector<uint8_t> buildExtensionsBlob(std::string_view sni)
{
    std::vector<uint8_t> blob;
    auto put16 = [&](uint16_t v) {
        blob.push_back(static_cast<uint8_t>(v >> 8));
        blob.push_back(static_cast<uint8_t>(v & 0xFF));
    };
    auto putExt = [&](uint16_t type, const std::vector<uint8_t>& data) {
        put16(type);
        put16(static_cast<uint16_t>(data.size()));
        blob.insert(blob.end(), data.begin(), data.end());
    };

    // ── SNI (0x0000) ──
    {
        std::vector<uint8_t> data;
        const uint16_t listLen = static_cast<uint16_t>(1 + 2 + sni.size());
        data.push_back(static_cast<uint8_t>(listLen >> 8));
        data.push_back(static_cast<uint8_t>(listLen & 0xFF));
        data.push_back(0);  // host_name
        data.push_back(static_cast<uint8_t>(sni.size() >> 8));
        data.push_back(static_cast<uint8_t>(sni.size() & 0xFF));
        data.insert(data.end(), sni.begin(), sni.end());
        putExt(0x0000, data);
    }

    // ── supported_groups (0x000a) ──
    {
        std::vector<uint8_t> data;
        data.push_back(0x00); data.push_back(0x04);  // list_len
        data.push_back(0x00); data.push_back(0x1D);  // x25519
        data.push_back(0x00); data.push_back(0x17);  // secp256r1
        putExt(0x000a, data);
    }

    // ── signature_algorithms (0x000d) ──
    {
        std::vector<uint8_t> data;
        data.push_back(0x00); data.push_back(0x06);  // list_len
        data.push_back(0x04); data.push_back(0x03);  // ecdsa_secp256r1_sha256
        data.push_back(0x08); data.push_back(0x04);  // rsa_pss_rsae_sha256
        data.push_back(0x04); data.push_back(0x01);  // rsa_pkcs1_sha256
        putExt(0x000d, data);
    }

    // ── supported_versions (0x002b) ──
    {
        std::vector<uint8_t> data;
        data.push_back(4);                            // list_len
        data.push_back(0x03); data.push_back(0x04);  // TLS 1.3
        data.push_back(0x03); data.push_back(0x03);  // TLS 1.2
        putExt(0x002b, data);
    }

    // ── key_share (0x0033) ──
    //    Одна группа x25519 с пустым key_exchange.
    //    constructClientHello подставит реальный публичный ключ
    //    через setPublicKey(0, ephemeralPrivateKey_).
    {
        std::vector<uint8_t> data;
        data.push_back(0x00); data.push_back(0x04);  // client_shares_len = 4
        data.push_back(0x00); data.push_back(0x1D);  // x25519
        data.push_back(0x00); data.push_back(0x00);  // key_exchange_len = 0
        putExt(0x0033, data);
    }

    // ── префикс длины блока расширений ──
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(blob.size() >> 8));
    out.push_back(static_cast<uint8_t>(blob.size() & 0xFF));
    out.insert(out.end(), blob.begin(), blob.end());
    return out;
}

} // namespace

void TlsProbeConnection::asyncProbe(std::string       sni,
                                    layers::IPAddress serverIP,
                                    uint16_t          serverPort,
                                    Config            cfg,
                                    Callback          cb)
{
    submit_([this, sni = std::move(sni), serverIP, serverPort, cfg,
             cb = std::move(cb)]() mutable
    {
        auto result = probeBlocking(sni, serverIP, serverPort, cfg);
        cb(std::move(result));
    });
}

TlsProbeResult TlsProbeConnection::probeBlocking(std::string_view sni,
                                                 const layers::IPAddress& serverIP,
                                                 uint16_t serverPort,
                                                 const Config& cfg)
{
    TlsProbeResult result;

    // ── 1. Сокет ──
    ScopedFd fd{::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)};
    if (!fd.valid())
    {
        result.status = TlsProbeResult::Status::ConnectFailed;
        result.error  = std::strerror(errno);
        return result;
    }

    const sockaddr_in sa = toSockaddr(serverIP, serverPort);
    if (!connectWithTimeout(fd.get(), sa, cfg.connectTimeout))
    {
        result.status = TlsProbeResult::Status::ConnectTimeout;
        result.error  = "connect timeout/failure";
        return result;
    }

    // ── 2. TLS-сессия в активном режиме ──
    tls::RecordPool pool{cfg.recordPoolSize};
    tls::Session    session{pool};
    session.setMonitor(false);   // реальный handshake
    session.setVersion(cfg.preferredVersion);

    // ── 3. ClientHello ──
    auto chBytes = buildClientHelloRecord(sni, cfg.preferredVersion,
                                          pool, session);
    if (chBytes.empty())
    {
        result.status = TlsProbeResult::Status::TlsError;
        result.error  = "build ClientHello failed";
        return result;
    }

    if (!sendAll(fd.get(), chBytes.data(), chBytes.size()))
    {
        result.status = TlsProbeResult::Status::ConnectFailed;
        result.error  = "send ClientHello failed";
        return result;
    }

    // ── 4. Читаем ServerHello + Certificate ──
    const auto deadline = std::chrono::steady_clock::now() + cfg.handshakeTimeout;
    bool gotCertificate = false;
    std::array<uint8_t, 16384> inBuf{};

    while (!gotCertificate)
    {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
        {
            result.status = TlsProbeResult::Status::HandshakeTimeout;
            result.error  = "handshake timeout";
            return result;
        }

        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        const int ev = pollOne(fd.get(), POLLIN, remaining);
        if (ev == 0)
        {
            result.status = TlsProbeResult::Status::HandshakeTimeout;
            result.error  = "handshake timeout";
            return result;
        }
        if (ev < 0)
        {
            result.status = TlsProbeResult::Status::TlsError;
            result.error  = "poll error";
            return result;
        }

        const ssize_t n = ::recv(fd.get(), inBuf.data(), inBuf.size(), 0);
        if (n <= 0)
        {
            result.status = TlsProbeResult::Status::TlsError;
            result.error  = (n == 0) ? "server closed" : "recv error";
            return result;
        }

        session.readRecords({inBuf.data(), static_cast<size_t>(n)});

        session.processPendingRecords(
            /*sideIndex=*/1,
            [&](int8_t side, tls::Record* rec)
            {
                using namespace snet::tls;

                snet::tls::PrintRecord(side, &session, rec);

                if (rec->getType() != RecordType::Handshake)
                    return;

                switch (rec->getHandshakeType())
                {
                case HandshakeType::ServerHelloCode:
                {
                    const auto& sh = rec->getHandshake<ServerHello>();
                    session.processServerHello(sh);
                    result.version     = session.getVersion();
                    result.cipherSuite = session.getInfo().cipherSuite;
                    break;
                }
                case HandshakeType::CertificateCode:
                {
                    result.chain = extractChain(
                        rec->getHandshake<Certificate>());
                    gotCertificate = true;
                    break;
                }
                default:
                    break;
                }
            });

        // Дренируем outgoing (CCS / Finished / etc.), чтобы сервер не
        // закрыл соединение.
        std::array<uint8_t, 4096> tmp{};
        const size_t w = session.writeRecords({tmp.data(), tmp.size()});
        if (w > 0)
            sendAll(fd.get(), tmp.data(), w);
    }

    if (result.chain.empty())
    {
        result.status = TlsProbeResult::Status::NoCertificate;
        return result;
    }

    result.status = TlsProbeResult::Status::Ok;
    return result;
}

} // namespace snet::proxy