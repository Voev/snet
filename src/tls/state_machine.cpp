#include <algorithm>
#include <limits>

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>

#include <snet/tls/state_machine.hpp>
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

StateMachine::StateMachine(const Settings& settings)
    : Connection(settings.createConnection())
    , lowerLayer_(nullptr)
    , alert_()
{

    setInfoCallback(::infoCallback);
    setIndexData(::getInfoCallbackDataIndex(), &alert_);

    if (settings.side() == Side::Server)
    {
        setAcceptState();
        setServerCallback(::serverCertCallback, nullptr);
    }
    else
    {
        setConnectState();
    }

    BIO* upperLayer{nullptr};
    BIO* lowerLayer{nullptr};
    crypto::ThrowIfFalse(0 < BIO_new_bio_pair(&upperLayer, 0, &lowerLayer, 0));
    setBio(upperLayer, upperLayer);

    lowerLayer_ = lowerLayer;
}

StateMachine::~StateMachine() noexcept
{
    BIO_free(lowerLayer_);
}

StateMachine::StateMachine(StateMachine&& other) noexcept
    : Connection(std::move(other.ssl_))
    , lowerLayer_(std::move(other.lowerLayer_))
    , alert_(std::move(other.alert_))
{
}

StateMachine& StateMachine::operator=(StateMachine&& other) noexcept
{
    if (this != &other)
    {
        ssl_ = std::move(other.ssl_);
        lowerLayer_ = std::move(other.lowerLayer_);
        alert_ = std::move(other.alert_);
    }
    return *this;
}

const Alert& StateMachine::getAlert() const noexcept
{
    return alert_;
}

void StateMachine::clear() noexcept
{
    cleanup();
    alert_ = Alert();
}

Want StateMachine::handshake(const std::uint8_t* bufferIn, const std::size_t bufferInSize,
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
    result = doHandshake();
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

Want StateMachine::decrypt(std::uint8_t* bufferIn, std::size_t bufferInSize,
                           std::uint8_t* bufferOut, std::size_t* bufferOutSize,
                           std::error_code& ec) noexcept
{

    if (bufferIn && bufferInSize > 0)
    {
        if (!lowerLayerWrite(bufferIn, bufferInSize, ec))
        {
            return Want::Nothing;
        }
    }

    auto pendingOutputBefore = BIO_ctrl_pending(lowerLayer_);
    auto result = doRead(bufferOut, *bufferOutSize);
    auto pendingOutputAfter = BIO_ctrl_pending(lowerLayer_);

    return handleResult(result, pendingOutputBefore, pendingOutputAfter, ec);
}

Want StateMachine::encrypt(std::uint8_t* bufferIn, std::size_t bufferInSize,
                           std::uint8_t* bufferOut, std::size_t* bufferOutSize,
                           std::error_code& ec) noexcept
{
    auto pendingOutputBefore = BIO_ctrl_pending(lowerLayer_);
    auto result = doWrite(bufferIn, bufferInSize);
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

Want StateMachine::closeNotify(std::uint8_t* buffer, std::size_t* bufferSize,
                               std::error_code& ec) noexcept
{

    std::size_t pendingBufferSize = BIO_ctrl_pending(lowerLayer_);
    if (pendingBufferSize == 0)
    {
        doShutdown();
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

Want StateMachine::handleResult(int result, std::size_t before, std::size_t after,
                                std::error_code& ec) noexcept
{
    int sslError = getError(result);
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

std::size_t StateMachine::lowerLayerRead(std::uint8_t* buffer, std::size_t length,
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

std::size_t StateMachine::lowerLayerWrite(const std::uint8_t* buffer, std::size_t length,
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

std::size_t StateMachine::lowerLayerPending() const noexcept
{
    return BIO_ctrl_pending(lowerLayer_);
}

} // namespace snet::tls
