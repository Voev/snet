/// @file
/// @brief Declaration of the SecretNode class.

#pragma once
#include <snet/crypto/secret.hpp>
#include <snet/tls/version.hpp>

namespace snet::tls
{

struct SecretNode
{
    crypto::Secret masterSecret;
    crypto::Secret clientEarlyTrafficSecret;
    crypto::Secret clientHndTrafficSecret;
    crypto::Secret clientAppTrafficSecret;
    crypto::Secret serverHndTrafficSecret;
    crypto::Secret serverAppTrafficSecret;

    bool isValid(const ProtocolVersion version) const noexcept;
};

} // namespace snet::tls
