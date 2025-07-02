#pragma once
#include <casket/nonstd/span.hpp>
#include <vector>
#include <cstdint>
#include <snet/crypto/typedefs.hpp>

namespace snet::crypto
{

std::vector<uint8_t> signDigest(Key* privateKey, const Hash* hash, nonstd::span<const uint8_t> messageDigest);

bool verifyDigest(Key* publicKey, const Hash* hash, nonstd::span<const uint8_t> messageDigest,
                  nonstd::span<const uint8_t> signature);

} // namespace snet::crypto