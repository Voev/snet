#pragma once
#include <string_view>
#include <cstdint>
#include <vector>
#include <span>

#include <snet/tls/secret_node.hpp>

#include <openssl/evp.h>

namespace snet::tls
{

void ssl3Prf(const Secret& secret, std::span<const uint8_t> clientRandom,
             std::span<const uint8_t> serverRandom, std::span<uint8_t> out);

void tls1Prf(std::string_view algorithm, const Secret& secret, std::string_view label,
             std::span<const uint8_t> clientRandom, std::span<const uint8_t> serverRandom,
             std::span<uint8_t> out);

std::vector<uint8_t> hkdfExpandLabel(const EVP_MD* md, const Secret& secret, std::string_view label,
                                     std::span<const uint8_t> context, const size_t length);

} // namespace snet::tls