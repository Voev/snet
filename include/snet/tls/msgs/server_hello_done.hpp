#pragma once
#include <casket/nonstd/span.hpp>
#include <casket/utils/exception.hpp>
#include <snet/tls/meta_info.hpp>


namespace snet::tls
{

class Session;

/// @brief Represents a Server Hello Done message in TLS protocol.
///
/// This message is sent by the server to indicate that it has finished
/// sending its hello messages and associated extensions. It signals to
/// the client that it should proceed with the next phase of the handshake.
/// The Server Hello Done message has no content (zero bytes).
struct ServerHelloDone final
{
    /// @brief Deserialize a Server Hello Done message from raw data.
    ///
    /// @param[in] input Raw bytes containing the Server Hello Done message.
    ///                  Must be empty for a valid Server Hello Done.
    ///
    /// @return Constructed ServerHelloDone object.
    ///
    /// @throws casket::Exception if input is not empty (malformed message).
    static ServerHelloDone deserialize(nonstd::span<const uint8_t> input)
    {
        casket::ThrowIfFalse(input.size() == 0, "Malformed ServerHelloDone message");
        return ServerHelloDone();
    }

    /// @brief Serialize the Server Hello Done message to a byte buffer.
    ///
    /// Since Server Hello Done is an empty message, this function performs
    /// no actual serialization and always returns 0.
    ///
    /// @param[in] output Buffer to write the serialized data to (unused).
    /// @param[in] session Session context for serialization (unused).
    ///
    /// @return Always returns 0 as no bytes are written.
    size_t serialize(nonstd::span<uint8_t> output, const Session& session) const
    {
        (void)output;
        (void)session;
        return 0;
    }
};

} // namespace snet::tls