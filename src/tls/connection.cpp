#include <openssl/err.h>

#include <snet/crypto/exception.hpp>

#include <snet/tls/connection.hpp>
#include <snet/tls/settings.hpp>

#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::tls
{

Connection::Connection(SSL* ssl)
    : ssl_(ssl)
{
    casket::ThrowIfTrue(ssl_ == nullptr, "Invalid argument");
}

Connection::~Connection() noexcept
{
}

Connection::Connection(Connection&& other) noexcept
    : ssl_(std::move(other.ssl_))
{
}

Connection& Connection::operator=(Connection&& other) noexcept
{
    if (this != &other)
    {
        ssl_ = std::move(other.ssl_);
    }
    return *this;
}

void Connection::setMinVersion(ProtocolVersion version)
{
    crypto::ThrowIfFalse(SSL_set_min_proto_version(ssl_, static_cast<int>(version.code())));
}

void Connection::setMaxVersion(ProtocolVersion version)
{
    crypto::ThrowIfFalse(SSL_set_max_proto_version(ssl_, static_cast<int>(version.code())));
}

void Connection::setVersion(ProtocolVersion version)
{
    setMinVersion(version);
    setMaxVersion(version);
}

void Connection::setIndexData(int index, void* data)
{
    crypto::ThrowIfFalse(0 < SSL_set_ex_data(ssl_, index, data));
}

int Connection::getError(int ret) const noexcept
{
    return SSL_get_error(ssl_, ret);
}

void Connection::setSocket(int fd)
{
    crypto::ThrowIfFalse(0 < SSL_set_fd(ssl_, fd));
}

void Connection::setSession(SSL_SESSION* session)
{
    crypto::ThrowIfFalse(0 < SSL_set_session(ssl_, session));
}

SslSessionPtr Connection::getSession()
{
    return SslSessionPtr{SSL_get1_session(ssl_)};
}

void Connection::setExtHostName(std::string_view hostname)
{
    crypto::ThrowIfFalse(0 < SSL_set_tlsext_host_name(ssl_, hostname.data()));
}

bool Connection::handshakeDone() const noexcept
{
    return SSL_is_init_finished(ssl_);
}

int Connection::doHandshake() noexcept
{
    return SSL_do_handshake(ssl_);
}

int Connection::doShutdown() noexcept
{
    return SSL_shutdown(ssl_);
}

int Connection::doRead(std::uint8_t* data, std::size_t length) noexcept
{
    return SSL_read(ssl_, data, length < INT_MAX ? static_cast<int>(length) : INT_MAX);
}

int Connection::doWrite(const std::uint8_t* data, std::size_t length) noexcept
{
    return SSL_write(ssl_, data, length < INT_MAX ? static_cast<int>(length) : INT_MAX);
}

} // namespace snet::tls