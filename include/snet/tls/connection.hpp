/// @file
/// @brief Declaration of the TLS connection class.

#pragma once
#include <functional>
#include <snet/tls/settings.hpp>
#include <snet/tls/types.hpp>
#include <snet/crypto/pointers.hpp>

namespace snet::tls
{

/// @brief Class representing a TLS connection.
class Connection final
{
public:
    using Operation = std::function<int(void*, std::size_t)>;

    /// @brief Enum representing the state of the connection.
    enum class Want
    {
        AlreadyCreated = -3,
        InputAndRetry = -2,
        OutputAndRetry = -1,
        Nothing = 0,
        Output = 1
    };

    /// @brief Constructor with settings.
    /// @param settings The TLS settings.
    explicit Connection(Settings& settings);

    /// @brief Destructor.
    ~Connection() noexcept;

    Connection(Connection&& other) noexcept;
    Connection& operator=(Connection&& other) noexcept;

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

    /// @brief Performs the handshake.
    /// @return The state of the connection after the handshake.
    Want handshake();

    /// @brief Shuts down the connection.
    /// @return The state of the connection after the shutdown.
    Want shutdown();

    /// @brief Reads data from the connection.
    /// @param data The buffer to read data into.
    /// @param dataLength The length of the data to read.
    /// @param bytesTransferred The number of bytes transferred.
    /// @return The state of the connection after the read.
    Want read(std::uint8_t* data, const std::size_t dataLength,
              std::size_t& bytesTransferred);

    /// @brief Writes data to the connection.
    /// @param data The buffer to write data from.
    /// @param dataLength The length of the data to write.
    /// @param bytesTransferred The number of bytes transferred.
    /// @return The state of the connection after the write.
    Want write(std::uint8_t* data, const std::size_t dataLength,
               std::size_t& bytesTransferred);

    /// @brief Performs the handshake operation.
    /// @param data The buffer to operate on.
    /// @param length The length of the data.
    /// @return The result of the handshake operation.
    int doHandshake(void*, std::size_t);

private:
    /// @brief Performs an operation on the connection.
    /// @param op The operation to perform.
    /// @param data The buffer to operate on.
    /// @param length The length of the data.
    /// @param bytesTransferred The number of bytes transferred.
    /// @return The state of the connection after the operation.
    Want perform(const Operation& op, void* data, std::size_t length,
                 std::size_t* bytesTransferred);

    /// @brief Performs the shutdown operation.
    /// @param data The buffer to operate on.
    /// @param length The length of the data.
    /// @return The result of the shutdown operation.
    int doShutdown(void*, std::size_t);

    /// @brief Performs the read operation.
    /// @param data The buffer to read data into.
    /// @param length The length of the data.
    /// @return The result of the read operation.
    int doRead(void* data, std::size_t length);

    /// @brief Performs the write operation.
    /// @param data The buffer to write data from.
    /// @param length The length of the data.
    /// @return The result of the write operation.
    int doWrite(void* data, std::size_t length);

private:
    SslPtr ssl_;
    crypto::BioPtr extBio_;
};

} // namespace snet::tls