#include <openssl/err.h>

#include <snet/tls/connection.hpp>
#include <snet/tls/settings.hpp>
#include <snet/tls/error_code.hpp>

#include <snet/utils/error_code_exception.hpp>

namespace snet::tls
{

Connection::Connection(Settings& settings)
    : ssl_(SSL_new(settings.ctx_))
{
    if (!ssl_)
    {
        throw std::bad_alloc();
    }

    SSL_set_mode(ssl_, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_set_mode(ssl_, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_set_mode(ssl_, SSL_MODE_RELEASE_BUFFERS);

    BIO* intBio{nullptr};
    BIO* extBio{nullptr};

    if (!BIO_new_bio_pair(&intBio, 0, &extBio, 0))
    {
        throw utils::ErrorCodeException(GetLastError());
    }

    SSL_set_bio(ssl_, intBio, intBio);
    extBio_.reset(extBio);

    if (settings.side() == Side::Client)
    {
        SSL_set_connect_state(ssl_);
    }
    else
    {
        SSL_set_accept_state(ssl_);
    }
}

Connection::~Connection() noexcept
{
}

Connection::Connection(Connection&& other) noexcept
    : ssl_(std::move(other.ssl_))
    , extBio_(std::move(other.extBio_))
{
}

Connection& Connection::operator=(Connection&& other) noexcept
{
    if (this != &other)
    {
        ssl_ = std::move(other.ssl_);
        extBio_ = std::move(other.extBio_);
    }
    return *this;
}

void Connection::setSocket(int fd)
{
    if (0 >= SSL_set_fd(ssl_, fd))
    {
        throw utils::ErrorCodeException(GetLastError());
    }
}

bool Connection::handshakeDone() const noexcept
{
    return SSL_is_init_finished(ssl_);
}

Connection::Want Connection::handshake()
{
    Operation op = std::bind(&Connection::doHandshake, this,
                             std::placeholders::_1, std::placeholders::_2);
    return perform(op, nullptr, 0, 0);
}

Connection::Want Connection::shutdown()
{
    Operation op = std::bind(&Connection::doShutdown, this,
                             std::placeholders::_1, std::placeholders::_2);
    return perform(op, nullptr, 0, 0);
}

Connection::Want Connection::read(std::uint8_t* data,
                                  const std::size_t dataLength,
                                  std::size_t& bytesTransferred)
{
    if (dataLength == 0)
    {
        return Want::Nothing;
    }
    Operation op = std::bind(&Connection::doRead, this, std::placeholders::_1,
                             std::placeholders::_2);
    return perform(op, data, dataLength, &bytesTransferred);
}

Connection::Want Connection::write(std::uint8_t* data,
                                   const std::size_t dataLength,
                                   std::size_t& bytesTransferred)
{
    if (dataLength == 0)
    {
        return Want::Nothing;
    }
    Operation op = std::bind(&Connection::doWrite, this, std::placeholders::_1,
                             std::placeholders::_2);
    return perform(op, const_cast<std::uint8_t*>(data), dataLength,
                   &bytesTransferred);
}

Connection::Want Connection::perform(const Operation& op, void* data, std::size_t length,
                         std::size_t* bytesTransferred)
{

    std::size_t pendingOutputBefore = BIO_ctrl_pending(extBio_);
    ERR_clear_error();
    int result = op(data, length);
    int sslError = SSL_get_error(ssl_, result);
    std::size_t pendingOutputAfter = BIO_ctrl_pending(extBio_);

    if (sslError == SSL_ERROR_SSL)
    {
        return pendingOutputAfter > pendingOutputBefore ? Want::Output
                                                        : Want::Nothing;
    }

    if (sslError == SSL_ERROR_SYSCALL)
    {
        return pendingOutputAfter > pendingOutputBefore ? Want::Output
                                                        : Want::Nothing;
    }

    if (result > 0 && bytesTransferred)
        *bytesTransferred = static_cast<std::size_t>(result);

    if (sslError == SSL_ERROR_WANT_WRITE)
    {
        return Want::OutputAndRetry;
    }
    else if (pendingOutputAfter > pendingOutputBefore)
    {
        return result > 0 ? Want::Output : Want::OutputAndRetry;
    }
    else if (sslError == SSL_ERROR_WANT_READ)
    {
        return Want::InputAndRetry;
    }
    return Want::Nothing;
}

int Connection::doHandshake(void*, std::size_t)
{
    return SSL_do_handshake(ssl_);
}

int Connection::doShutdown(void*, std::size_t)
{
    int result = SSL_shutdown(ssl_);
    if (result == 0)
        result = SSL_shutdown(ssl_);
    return result;
}

int Connection::doRead(void* data, std::size_t length)
{
    return SSL_read(ssl_, data,
                    length < INT_MAX ? static_cast<int>(length) : INT_MAX);
}

int Connection::doWrite(void* data, std::size_t length)
{
    return SSL_write(ssl_, data,
                     length < INT_MAX ? static_cast<int>(length) : INT_MAX);
}

} // namespace snet::tls