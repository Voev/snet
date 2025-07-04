/// @file
/// @brief Declaration of the HandshakeHash class.

#pragma once
#include <casket/nonstd/span.hpp>
#include <vector>
#include <string_view>
#include <snet/crypto/typedefs.hpp>

namespace snet::tls
{

/// @brief Class for handling handshake hash operations.
class HandshakeHash final
{
public:
    /// @brief Default constructor.
    HandshakeHash();

    /// @brief Destructor.
    ~HandshakeHash() noexcept;

    /// @brief Updates the handshake hash with input data.
    /// @param in The input data to update the hash with.
    void update(nonstd::span<const uint8_t> in);

    /// @brief Finalizes the handshake hash and returns the result.
    /// @param algorithm The hash algorithm to use.
    /// @return The final hash value.
    nonstd::span<uint8_t> final(HashCtx* hashCtx, const Hash* hashAlg, nonstd::span<uint8_t> buffer) const;

    /// @brief Gets the contents of the handshake messages.
    /// @return The contents of the handshake messages.
    const std::vector<uint8_t>& getContents() const;

    /// @brief Resets the handshake hash.
    void reset();

private:
    std::vector<uint8_t> messages_;
};

} // namespace snet::tls