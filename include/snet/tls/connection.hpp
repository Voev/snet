/// @file
/// @brief Declaration of the TLS connection class.

#pragma once
#include <functional>
#include <snet/tls/types.hpp>
#include <snet/crypto/pointers.hpp>
#include <snet/tls/version.hpp>
#include <snet/utils/noncopyable.hpp>

namespace snet::tls
{

/// @brief Class representing a TLS connection.
class Connection
{
public:
    friend class Settings;

    /// @brief Destructor.
    virtual ~Connection() noexcept;

    Connection(Connection&& other) noexcept;
    Connection& operator=(Connection&& other) noexcept;

    void setIndexData(int index, void* data);

    int getError(int ret) const noexcept;

    void setBio(BIO* rbio, BIO* wbio) noexcept
    {
        SSL_set_bio(ssl_, rbio, wbio);
    }

    void setServerCallback(int (*cb)(SSL* ssl, void* arg), void* arg)
    {
        SSL_set_cert_cb(ssl_, cb, arg);
    }

    void setInfoCallback(void (*cb)(const SSL*, int, int))
    {
        SSL_set_info_callback(ssl_, cb);
    }

    void setConnectState() noexcept
    {
        SSL_set_connect_state(ssl_);
    }

    void setAcceptState() noexcept
    {
        SSL_set_accept_state(ssl_);
    }

    bool beforeHandshake() const noexcept
    {
        return SSL_in_before(ssl_);
    }

    bool afterHandshake() const noexcept
    {
        return SSL_is_init_finished(ssl_);
    }

    void cleanup() noexcept
    {
        SSL_clear(ssl_);
    }

    bool isClosed() const noexcept
    {
        return SSL_get_shutdown(ssl_) != 0;
    }

    void setMinVersion(ProtocolVersion version);

    void setMaxVersion(ProtocolVersion version);

    void setVersion(ProtocolVersion version);

    /// @brief Sets the socket file descriptor.
    /// @param fd The socket file descriptor.
    void setSocket(int fd);

    /// @brief Sets the session for the connection.
    /// @param session The SSL session.
    void setSession(SSL_SESSION* session);

    /// @brief Gets the session of the connection.
    /// @return The SSL session.
    SslSessionPtr getSession();

    /// @brief Sets the external host name.
    /// @param hostname The external host name.
    void setExtHostName(std::string_view hostname);

    /// @brief Checks if the handshake is done.
    /// @return True if the handshake is done, false otherwise.
    bool handshakeDone() const noexcept;

    /// @brief Performs the handshake operation.
    /// @return The result of the handshake operation.
    int doHandshake() noexcept;

    /// @brief Performs the shutdown operation.
    /// @return The result of the shutdown operation.
    int doShutdown() noexcept;

    /// @brief Performs the read operation.
    /// @param data The buffer to read data into.
    /// @param length The length of the data.
    /// @return The result of the read operation.
    int doRead(std::uint8_t* data, std::size_t length) noexcept;

    /// @brief Performs the write operation.
    /// @param data The buffer to write data from.
    /// @param length The length of the data.
    /// @return The result of the write operation.
    int doWrite(const std::uint8_t* data, std::size_t length) noexcept;

protected:
    explicit Connection(SSL* ssl);

protected:
    SslPtr ssl_;
};

} // namespace snet::tls