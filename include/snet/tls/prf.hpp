/// @file
/// @brief Declaration of functions for Pseudo-Random Functions (PRF) used in TLS.

#pragma once
#include <string_view>
#include <cstdint>
#include <vector>
#include <casket/nonstd/span.hpp>
#include <snet/tls/secret_node.hpp>

namespace snet::tls
{

/// @brief SSL 3.0 Pseudo-Random Function (PRF).
///
/// @param secret The secret key.
/// @param clientRandom The client's random value.
/// @param serverRandom The server's random value.
/// @param out The output buffer for the generated pseudo-random data.
void ssl3Prf(const Secret& secret, nonstd::span<const uint8_t> clientRandom, nonstd::span<const uint8_t> serverRandom,
             nonstd::span<uint8_t> out);

/// @brief TLS 1.0/1.1/1.2 Pseudo-Random Function (PRF).
///
/// @param algorithm The PRF algorithm.
/// @param secret The secret key.
/// @param label The label for the PRF.
/// @param clientRandom The client's random value.
/// @param serverRandom The server's random value.
/// @param out The output buffer for the generated pseudo-random data.
void tls1Prf(std::string_view algorithm, const Secret& secret, std::string_view label,
             nonstd::span<const uint8_t> clientRandom, nonstd::span<const uint8_t> serverRandom,
             nonstd::span<uint8_t> out);

void HkdfExpand(std::string_view algorithm, nonstd::span<const uint8_t> secret, nonstd::span<const uint8_t> label,
                nonstd::span<const uint8_t> data, nonstd::span<uint8_t> out);

void DeriveFinishedKey(std::string_view algorithm, nonstd::span<const uint8_t> secret, nonstd::span<uint8_t> out);

void DeriveKey(std::string_view algorithm, nonstd::span<const uint8_t> secret, nonstd::span<uint8_t> out);

void DeriveIV(std::string_view algorithm, nonstd::span<const uint8_t> secret, nonstd::span<uint8_t> out);

void UpdateTrafficSecret(std::string_view algorithm, nonstd::span<uint8_t> secret);

} // namespace snet::tls