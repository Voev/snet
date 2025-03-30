#pragma once
#include <cstdint>
#include <system_error>
#include <functional>
#include <snet/crypto/pointers.hpp>
#include <snet/tls/alert.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/version.hpp>

namespace snet::tls
{

class Settings;

enum class Want
{
    Nothing = 0,
    Input,
    Output,
    Certificate,
};

class Connection2 final
{
public:
    explicit Connection2(const Settings& settings);

    ~Connection2() noexcept;

    Connection2(const Connection2& other) = delete;
    Connection2& operator=(const Connection2& other) = delete;

    Connection2(Connection2&& other) noexcept;
    Connection2& operator=(Connection2&& other) noexcept;

    Want handshake(std::uint8_t* bufferIn, std::size_t bufferInSize, std::uint8_t* bufferOut,
                   std::size_t* bufferOutSize, std::error_code& ec) noexcept;

    Want decrypt(std::uint8_t* bufferIn, std::size_t bufferInSize, std::uint8_t* bufferOut,
                 std::size_t* bufferOutSize, std::error_code& ec) noexcept;

    Want encrypt(std::uint8_t* bufferIn, std::size_t bufferInSize, std::uint8_t* bufferOut,
                 std::size_t* bufferOutSize, std::error_code& ec) noexcept;

    Want closeNotify(std::uint8_t* buffer, std::size_t* bufferSize, std::error_code& ec) noexcept;

    bool isClosed() const noexcept;

    void shutdown();

    crypto::CertPtr getPeerCert() const;

    void useCertificate(Cert* certificate);

    void usePrivateKey(Key* privateKey);

    void useCertificateWithKey(Cert* certificate, Key* privateKey);

    void checkPrivateKey() const;

    bool beforeHandshake() const;

    bool handshakeFinished() const;

    void setMinVersion(ProtocolVersion version);

    void setMaxVersion(ProtocolVersion version);

    void setVersion(ProtocolVersion version);

    ProtocolVersion getProtoVersion() const noexcept;

    const Alert& getAlert() const noexcept;

    bool isServer() const noexcept;

    void clear() noexcept;

    std::size_t lowerLayerRead(std::uint8_t* buffer, std::size_t length, std::error_code& ec) noexcept;

    std::size_t lowerLayerWrite(const std::uint8_t* buffer, std::size_t length, std::error_code& ec) noexcept;

    std::size_t upperLayerRead(std::uint8_t* buffer, std::size_t length, std::error_code& ec) noexcept;

    std::size_t upperLayerWrite(const std::uint8_t* buffer, std::size_t length, std::error_code& ec) noexcept;

    std::size_t lowerLayerPending() const noexcept;

private:
    Want handleResult(int result, std::size_t before, std::size_t after, std::error_code& ec) noexcept;

private:
    SSL* ssl_;        ///< Указатель на SSL структуру.
    Bio* lowerLayer_; ///< Указатель на BIO структуру.
    Alert alert_;     ///< Предупреждение TLS.
};

} // namespace snet::tls
