/// @file
/// @brief Declaration of the SecretNode class.

#pragma once
#include <snet/crypto/secure_array.hpp>
#include <snet/tls/version.hpp>

namespace snet::tls
{

struct SecretNode
{
    crypto::SecureArray<uint8_t, TLS_MASTER_SECRET_SIZE> masterSecret;
    crypto::SecureArray<uint8_t, TLS_MAX_KEY_LENGTH> clientEarlyTrafficSecret;
    crypto::SecureArray<uint8_t, TLS_MAX_KEY_LENGTH> clientHndTrafficSecret;
    crypto::SecureArray<uint8_t, TLS_MAX_KEY_LENGTH> clientAppTrafficSecret;
    crypto::SecureArray<uint8_t, TLS_MAX_KEY_LENGTH> serverHndTrafficSecret;
    crypto::SecureArray<uint8_t, TLS_MAX_KEY_LENGTH> serverAppTrafficSecret;

    bool isValid(const ProtocolVersion version) const noexcept;
};

} // namespace snet::tls
