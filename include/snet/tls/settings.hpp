#pragma once
#include <snet/tls/types.hpp>
#include <snet/utils/noncopyable.hpp>

namespace snet::tls
{

/// @brief Режим проверки цепочки сертификатов противоположной стороны.
enum class VerifyMode
{
    None = 0x00,
    Peer = 0x01,
    FailIfNoPeerCert = 0x02,
    ClientOnce = 0x04,
    PostHandhsake = 0x08
};

using VerifyCallback = int (*)(int, X509_STORE_CTX*);

struct Settings : public utils::NonCopyable
{
public:
    friend class Handle;

    explicit Settings(Side side);

    virtual ~Settings() noexcept;

    virtual Side side() const = 0;

    void loadPrivateKey(std::string_view filename);

    void usePrivateKey(EVP_PKEY* privateKey);

    void loadCertificate(std::string_view filename);

    void useCertificate(X509* certificate);

    void setMaxVersion(ProtocolVersion version);

    void setMinVersion(ProtocolVersion version);

    void setVerifyCallback(VerifyMode mode, VerifyCallback callback) noexcept;

    void setMode(Mode mode);

private:
    SslCtxPtr ctx_;
};

class ClientSettings final : public Settings
{
public:
    ClientSettings()
        : Settings(Side::Client)
    {
    }
    ~ClientSettings() = default;

    Side side() const override
    {
        return Side::Client;
    }
};

class ServerSettings final : public Settings
{
public:
    ServerSettings()
        : Settings(Side::Server)
    {
    }
    ~ServerSettings() = default;
    Side side() const override
    {
        return Side::Server;
    }
};

} // namespace snet::tls