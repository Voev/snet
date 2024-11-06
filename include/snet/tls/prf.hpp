#pragma once
#include <string_view>
#include <cstdint>
#include <vector>
#include <span>

#include <snet/tls/secret_node.hpp>

#include <openssl/evp.h>

namespace snet::tls
{

void ssl3_prf(const Secret& secret, std::string_view usage,
              std::span<const uint8_t> rnd1, std::span<const uint8_t> rnd2,
              std::span<uint8_t> out);

void tls_prf(const Secret& secret, std::string_view usage,
             std::span<const uint8_t> rnd1, std::span<const uint8_t> rnd2,
             std::span<uint8_t> out);

void tls12_prf(const EVP_MD* md, const Secret& secret, std::string_view usage,
               std::span<const uint8_t> rnd1, std::span<const uint8_t> rnd2,
               std::span<uint8_t> out);

std::vector<uint8_t> hkdfExpandLabel(const EVP_MD* md, const Secret& secret,
                                     std::string_view label,
                                     std::span<const uint8_t> context,
                                     const size_t length);

} // namespace snet::tls