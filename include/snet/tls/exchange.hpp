#pragma once
#include <snet/crypto/secure_vector.hpp>
#include <snet/crypto/typedefs.hpp>

namespace snet::tls
{

SecureVector<uint8_t> ExchangeSecret(Key* privateKey, Key* publicKey, bool isTLSv3);

} // namespace snet::tls