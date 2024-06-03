#pragma once
#include <stdexcept>
#include <string_view>
#include <snet/tls/types.hpp>
#include <snet/tls/error_code.hpp>
#include <snet/utils/noncopyable.hpp>
#include <snet/utils/error_code_exception.hpp>

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

/// @brief Тип функции обратного вызова для обработки результатов проверки
/// цепочки сертификатов противоположной стороны.
using VerifyCallback = int (*)(int, X509_STORE_CTX*);

struct Context : public utils::NonCopyable
{
public:
    friend class Handle;

    explicit Context(const SSL_METHOD* meth);
    ~Context() noexcept;

    void loadPrivateKey(std::string_view filename,
                        std::error_code& ec) noexcept;

    inline void loadPrivateKey(EVP_PKEY* privateKey)
    {
        std::error_code ec;
        loadPrivateKey(privateKey);
        THROW_IF_ERROR(ec);
    }

    void usePrivateKey(EVP_PKEY* privateKey, std::error_code& ec) noexcept;

    inline void usePrivateKey(EVP_PKEY* privateKey)
    {
        std::error_code ec;
        usePrivateKey(privateKey);
        THROW_IF_ERROR(ec);
    }

    void loadCertificate(std::string_view filename,
                         std::error_code& ec) noexcept;

    inline void loadCertificate(X509* certificate)
    {
        std::error_code ec;
        loadCertificate(certificate);
        THROW_IF_ERROR(ec);
    }

    void useCertificate(X509* certificate, std::error_code& ec) noexcept;

    inline void useCertificate(X509* certificate)
    {
        std::error_code ec;
        useCertificate(certificate);
        THROW_IF_ERROR(ec);
    }

    void setMaxVersion(ProtocolVersion version, std::error_code& ec) noexcept;

    inline void setMaxVersion(ProtocolVersion version)
    {
        std::error_code ec;
        setMaxVersion(version, ec);
        THROW_IF_ERROR(ec);
    }

    void setMinVersion(ProtocolVersion version, std::error_code& ec) noexcept;

    inline void setMinVersion(ProtocolVersion version)
    {
        std::error_code ec;
        setMinVersion(version, ec);
        THROW_IF_ERROR(ec);
    }

    void setVerifyCallback(VerifyMode mode, VerifyCallback callback) noexcept;

private:
    SSL_CTX* ctx_{nullptr};
};

} // namespace verify