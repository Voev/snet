#include <algorithm>
#include <limits>

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>

#include <snet/tls/connection2.hpp>
#include <snet/tls/settings.hpp>

#include <snet/crypto/exception.hpp>

using namespace snet;

namespace
{

static constexpr std::size_t kDataLimit = std::numeric_limits<int>::max();

static int gInfoDataIndex{-1};

/// @brief Retrieves the data index for SSL warning/alert information storage.
/// @details Initializes and returns a unique index for storing alert information in SSL objects.
///          The index is cached after first initialization.
/// @return Index for storing alert information in SSL objects.
int getInfoCallbackDataIndex()
{
    if (gInfoDataIndex == -1)
    {
        gInfoDataIndex = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        if (gInfoDataIndex == -1)
        {
            throw crypto::Exception(crypto::GetLastError());
        }
    }
    return gInfoDataIndex;
}

/// @brief SSL information callback for handling warning/alert notifications.
/// @details This callback is triggered during SSL/TLS operations to provide status information
///          and alert notifications. It specifically handles alert messages by storing them
///          in the associated alert object.
/// @param s SSL structure pointer
/// @param where Bitmask indicating the callback location/phase
/// @param code Alert/warning code
void infoCallback(const SSL* s, int where, int code)
{
    tls::Alert* alert = static_cast<tls::Alert*>(SSL_get_ex_data(s, getInfoCallbackDataIndex()));
    if (alert && (where & SSL_CB_ALERT))
    {
        *alert = tls::Alert(code);
    }
}

/// @brief Server certificate selection callback.
/// @details This callback is invoked during the handshake when the server needs to select
///          a certificate. It implements a special case where returning -1 allows proper
///          handling when no server certificate is available at ClientHello reading stage.
/// @param ssl SSL structure pointer
/// @param arg User-defined argument (unused in this implementation)
/// @return 1 if certificate is available, -1 if no certificate is currently available
/// @note Returning -1 is crucial for proper handling of cases where server certificate
///       isn't available during initial ClientHello processing.
int serverCertCallback(SSL* ssl, void* arg)
{
    (void)arg;
    return !SSL_get_certificate(ssl) ? -1 : 1;
}

} // namespace

namespace snet::tls
{

Connection2::Connection2(const Settings& ctx)
    : ssl_(nullptr)
    , lowerLayer_(nullptr)
    , alert_()
{

    /// @todo: fix it.
    SslPtr ssl(SSL_new(ctx.getHandle()));
    crypto::ThrowIfFalse(ssl);

    SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_set_mode(ssl, SSL_MODE_RELEASE_BUFFERS);

    if (ctx.side() == Side::Client)
    {
        SSL_set_connect_state(ssl);
    }
    else
    {
        SSL_set_accept_state(ssl);
        SSL_set_cert_cb(ssl, ::serverCertCallback, nullptr);
    }

    SSL_set_info_callback(ssl, ::infoCallback);
    crypto::ThrowIfFalse(0 < SSL_set_ex_data(ssl, ::getInfoCallbackDataIndex(), &alert_));

    BIO* upperLayer{nullptr};
    BIO* lowerLayer{nullptr};
    crypto::ThrowIfFalse(0 < BIO_new_bio_pair(&upperLayer, 0, &lowerLayer, 0));
    SSL_set_bio(ssl.get(), upperLayer, upperLayer);

    ssl_ = ssl.release();
    lowerLayer_ = lowerLayer;
}

Connection2::~Connection2() noexcept
{
    BIO_free(lowerLayer_);
    SSL_free(ssl_);
}

Connection2::Connection2(Connection2&& other) noexcept
    : ssl_(std::move(other.ssl_))
    , lowerLayer_(std::move(other.lowerLayer_))
    , alert_(std::move(other.alert_))
{
}

Connection2& Connection2::operator=(Connection2&& other) noexcept
{
    if (this != &other)
    {
        ssl_ = std::move(other.ssl_);
        lowerLayer_ = std::move(other.lowerLayer_);
        alert_ = std::move(other.alert_);
    }
    return *this;
}

void Connection2::shutdown()
{
    crypto::ThrowIfFalse(1 == SSL_shutdown(ssl_));
}

crypto::CertPtr Connection2::getPeerCert() const
{
    return crypto::CertPtr{SSL_get1_peer_certificate(ssl_)};
}

bool Connection2::beforeHandshake() const
{
    return SSL_in_before(ssl_);
}

bool Connection2::handshakeFinished() const
{
    return SSL_is_init_finished(ssl_);
}

void Connection2::checkPrivateKey() const
{
    crypto::ThrowIfFalse(SSL_check_private_key(ssl_));
}

void Connection2::useCertificate(Cert* certificate)
{
    crypto::ThrowIfFalse(SSL_use_certificate(ssl_, certificate));
}

void Connection2::usePrivateKey(Key* privateKey)
{
    crypto::ThrowIfFalse(SSL_use_PrivateKey(ssl_, privateKey));
}

void Connection2::useCertificateWithKey(Cert* certificate, Key* privateKey)
{
    crypto::ThrowIfFalse(SSL_use_cert_and_key(ssl_, certificate, privateKey, nullptr, 1));
}

bool Connection2::isServer() const noexcept
{
    return SSL_is_server(ssl_);
}

void Connection2::setMinVersion(ProtocolVersion version)
{
    crypto::ThrowIfFalse(SSL_set_min_proto_version(ssl_, static_cast<int>(version.code())));
}

void Connection2::setMaxVersion(ProtocolVersion version)
{
    crypto::ThrowIfFalse(SSL_set_max_proto_version(ssl_, static_cast<int>(version.code())));
}

void Connection2::setVersion(ProtocolVersion version)
{
    setMinVersion(version);
    setMaxVersion(version);
}

ProtocolVersion Connection2::getProtoVersion() const noexcept
{
    return static_cast<ProtocolVersion>(SSL_version(ssl_));
}

const Alert& Connection2::getAlert() const noexcept
{
    return alert_;
}

void Connection2::clear() noexcept
{
    SSL_clear(ssl_);
    alert_ = Alert();
}

bool Connection2::isClosed() const noexcept
{
    return SSL_get_shutdown(ssl_) != 0;
}

Want Connection2::handshake(std::uint8_t* bufferIn, std::size_t bufferInSize,
                            std::uint8_t* bufferOut, std::size_t* bufferOutSize,
                            std::error_code& ec) noexcept
{

    std::size_t pendingOutputBefore;
    std::size_t pendingOutputAfter;
    int result;

    if (bufferIn && bufferInSize > 0)
    {
        if (!lowerLayerWrite(bufferIn, bufferInSize, ec))
        {
            return Want::Nothing;
        }
    }

    pendingOutputBefore = BIO_ctrl_pending(lowerLayer_);
    result = SSL_do_handshake(ssl_);
    pendingOutputAfter = BIO_ctrl_pending(lowerLayer_);

    auto want = handleResult(result, pendingOutputBefore, pendingOutputAfter, ec);

    if (ec)
        return Want::Nothing;

    if (bufferOutSize && pendingOutputAfter > 0)
    {
        if (pendingOutputAfter > *bufferOutSize)
        {
            *bufferOutSize = pendingOutputAfter;
            return Want::Output;
        }

        if (pendingOutputAfter > 0)
        {
            *bufferOutSize = lowerLayerRead(bufferOut, pendingOutputAfter, ec);
            if (!(*bufferOutSize))
            {
                return Want::Nothing;
            }
        }
        else
        {
            *bufferOutSize = 0U;
        }

        return *bufferOutSize == pendingOutputAfter ? Want::Nothing : Want::Output;
    }

    return want;
}

Want Connection2::decrypt(std::uint8_t* bufferIn, std::size_t bufferInSize, std::uint8_t* bufferOut,
                          std::size_t* bufferOutSize, std::error_code& ec) noexcept
{

    if (bufferIn && bufferInSize > 0)
    {
        if (!lowerLayerWrite(bufferIn, bufferInSize, ec))
        {
            return Want::Nothing;
        }
    }

    std::size_t bufferMaxSize = *bufferOutSize;
    auto pendingOutputBefore = BIO_ctrl_pending(lowerLayer_);
    auto result = SSL_read_ex(ssl_, bufferOut, bufferMaxSize, bufferOutSize);
    auto pendingOutputAfter = BIO_ctrl_pending(lowerLayer_);

    return handleResult(result, pendingOutputBefore, pendingOutputAfter, ec);
}

Want Connection2::encrypt(std::uint8_t* bufferIn, std::size_t bufferInSize, std::uint8_t* bufferOut,
                          std::size_t* bufferOutSize, std::error_code& ec) noexcept
{

    std::size_t writtenSize{0};
    auto pendingOutputBefore = BIO_ctrl_pending(lowerLayer_);
    auto result = SSL_write_ex(ssl_, bufferIn, bufferInSize, &writtenSize);
    auto pendingOutputAfter = BIO_ctrl_pending(lowerLayer_);

    auto want = handleResult(result, pendingOutputBefore, pendingOutputAfter, ec);
    if (want != Want::Output)
    {
        return want;
    }

    std::size_t bufferMaxSize = *bufferOutSize;
    *bufferOutSize = lowerLayerRead(bufferOut, bufferMaxSize, ec);
    return Want::Nothing;
}

Want Connection2::closeNotify(std::uint8_t* buffer, std::size_t* bufferSize, std::error_code& ec) noexcept
{

    std::size_t pendingBufferSize = BIO_ctrl_pending(lowerLayer_);
    if (pendingBufferSize == 0)
    {
        SSL_shutdown(ssl_);
        pendingBufferSize = BIO_ctrl_pending(lowerLayer_);
    }

    if (pendingBufferSize > *bufferSize)
    {
        *bufferSize = pendingBufferSize;
        return Want::Output;
    }

    if (pendingBufferSize > 0)
    {
        *bufferSize = lowerLayerRead(buffer, pendingBufferSize, ec);
        if (!(*bufferSize))
        {
            return Want::Nothing;
        }
    }
    else
    {
        *bufferSize = 0;
    }

    return Want::Nothing;
}

Want Connection2::handleResult(int result, std::size_t before, std::size_t after,
                               std::error_code& ec) noexcept
{
    int sslError = SSL_get_error(ssl_, result);
    if (sslError == SSL_ERROR_SSL || sslError == SSL_ERROR_SYSCALL)
    {
        ec = crypto::GetLastError();
        return after > before ? Want::Output : Want::Nothing;
    }
    else if (sslError == SSL_ERROR_WANT_X509_LOOKUP)
    {
        return Want::Certificate;
    }
    else if (sslError == SSL_ERROR_WANT_WRITE)
    {
        return Want::Output;
    }
    else if (after > before)
    {
        return Want::Output;
    }
    else if (sslError == SSL_ERROR_WANT_READ)
    {
        return Want::Input;
    }
    return Want::Nothing;
}

std::size_t Connection2::upperLayerRead(std::uint8_t* buffer, std::size_t length, std::error_code& ec) noexcept
{
    auto ret = SSL_read(ssl_, buffer, static_cast<int>(std::min(length, kDataLimit)));
    if (ret < 0)
    {
        ec = crypto::GetLastError();
        return 0U;
    }

    return static_cast<std::size_t>(ret);
}

std::size_t Connection2::upperLayerWrite(const std::uint8_t* buffer, std::size_t length, std::error_code& ec) noexcept
{
    auto ret = SSL_write(ssl_, buffer, static_cast<int>(std::min(length, kDataLimit)));
    if (ret < 0)
    {
        ec = crypto::GetLastError();
        return 0U;
    }

    return length;
}

std::size_t Connection2::lowerLayerRead(std::uint8_t* buffer, std::size_t length,
                                        std::error_code& ec) noexcept
{
    auto ret = BIO_read(lowerLayer_, buffer, static_cast<int>(std::min(length, kDataLimit)));
    if (ret < 0)
    {
        ec = crypto::GetLastError();
        return 0U;
    }

    return static_cast<std::size_t>(ret);
}

std::size_t Connection2::lowerLayerWrite(const std::uint8_t* buffer, std::size_t length,
                                         std::error_code& ec) noexcept
{
    auto ret = BIO_write(lowerLayer_, buffer, static_cast<int>(std::min(length, kDataLimit)));
    if (ret < 0)
    {
        ec = crypto::GetLastError();
        return 0U;
    }

    return static_cast<std::size_t>(ret);
}

std::size_t Connection2::lowerLayerPending() const noexcept
{
    return BIO_ctrl_pending(lowerLayer_);
}

} // namespace snet::tls
