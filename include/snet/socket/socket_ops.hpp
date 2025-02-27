/// @file
/// @brief Declaraion of socket operations functions.

#pragma once
#include <system_error>
#include <snet/socket/types.hpp>

namespace snet::socket
{

/// @brief Creates a socket and returns its descriptor.
///
/// @param domain The protocol family (e.g., AF_INET).
/// @param socktype The type of socket (e.g., SOCK_STREAM).
/// @param protocol The protocol to be used (e.g., IPPROTO_TCP).
/// @param ec Outputs the error code if socket creation fails.
///
/// @return A socket descriptor of type `SocketType`. If the creation fails, it returns an invalid socket descriptor.
SocketType CreateSocket(int domain, int socktype, int protocol, std::error_code& ec);

/// @brief Creates a socket using a protocol object for configuration.
///
/// @tparam Protocol Provides methods to get family, type, and protocol.
/// @param protocol Protocol instance with socket configuration methods.
/// @param ec Outputs error code if creation fails.
///
/// @return A `SocketType` descriptor; invalid if creation fails.
template <typename Protocol>
SocketType CreateSocket(const Protocol& protocol, std::error_code& ec)
{
    return CreateSocket(protocol.family(), protocol.type(), protocol.protocol(), ec);
}

/// @brief Closes an open socket.
///
/// @param sock The socket descriptor to close.
void CloseSocket(SocketType sock);

/// @brief Connects a socket to a specified address.
///
/// @param sock The socket descriptor to use for connection.
/// @param addr The destination address.
/// @param addrlen The length of the address.
/// @param ec Outputs the error code if the connection fails.
///
/// @return The socket descriptor if successful, otherwise an invalid descriptor.
SocketType Connect(SocketType sock, const SocketAddrType* addr, SocketLengthType addrlen,
                   std::error_code& ec);

/// Accepts a connection on a socket.
///
/// @param sock The socket descriptor on which to accept the connection.
/// @param addr Outputs the address of the connecting entity.
/// @param addrlen Initially specifies the size of `addr`, outputs the actual size of the returned address.
/// @param ec Outputs the error code if the accept operation fails.
///
/// @return A new socket descriptor for the accepted connection.
SocketType Accept(SocketType sock, SocketAddrType* addr, SocketLengthType* addrlen,
                  std::error_code& ec);

/// @brief Sets a socket option.
///
/// @param s The socket descriptor to configure.
/// @param level The level at which the option is defined.
/// @param optname The option name.
/// @param optval The option value.
/// @param optlen The size of the option value.
/// @param ec Outputs the error code if the operation fails.
///
/// @return Zero on success, or a negative value if the operation fails.
int SetSocketOption(SocketType s, int level, int optname, void* optval, size_t* optlen,
                    std::error_code& ec);

/// @brief Configures the linger option on a socket.
///
/// @param s The socket descriptor to configure.
/// @param onoff Linger active (non-zero) or disabled (zero).
/// @param linger Linger time in seconds (if onoff is non-zero).
/// @param ec Outputs the error code if the operation fails.
void SetLinger(SocketType s, int onoff, int linger, std::error_code& ec);

/// @brief Gets a socket option.
///
/// @param s The socket descriptor from which to retrieve the option.
/// @param level The level at which the option is defined.
/// @param optname The option name.
/// @param optval Outputs the option value.
/// @param optlen Input as the size of the buffer for `optval`, outputs the actual size of the returned option.
/// @param ec Outputs the error code if the operation fails.
///
/// @return Zero on success, or a negative value if the operation fails.
int GetSocketOption(SocketType s, int level, int optname, void* optval, size_t* optlen,
                    std::error_code& ec);

/// @brief Retrieves the last error for a socket.
///
/// @param s The socket to check.
///
/// @return `std::error_code` indicating the last socket error.
std::error_code GetSocketError(SocketType s);

/// @brief Sets a socket to blocking or non-blocking mode.
///
/// @param s The socket to configure.
/// @param value Set to `true` for non-blocking, `false` for blocking.
/// @param ec Output parameter for error codes.
void SetNonBlocking(SocketType s, bool value, std::error_code& ec);

} // namespace snet::socket