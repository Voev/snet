/// @file
/// @brief Declaration of the ClientRandom and ServerRandom types and their associated hash specialization.

#pragma once
#include <vector>
#include <cstdint>

namespace snet::tls {

/// @brief Alias for a vector of bytes representing the client's random value in the TLS handshake.
using ClientRandom = std::vector<uint8_t>;

/// @brief Alias for a vector of bytes representing the server's random value in the TLS handshake.
using ServerRandom = std::vector<uint8_t>;

} // namespace snet::tls

namespace std {

/// @brief Specialization of std::hash for snet::tls::ClientRandom.
template <>
struct hash<snet::tls::ClientRandom> {
    /// @brief Computes the hash value for a ClientRandom object.
    /// @param random The ClientRandom object to hash.
    /// @return The computed hash value.
    std::size_t operator()(const snet::tls::ClientRandom& random) const noexcept {
        std::size_t hash{0};
        for (auto byte : random) {
            hash = (hash << 5) - hash + byte;
        }
        return hash;
    }
};

} // namespace std