#pragma once
#include <cstdint>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/typedefs.hpp>
#include <snet/crypto/signature_scheme.hpp>

namespace snet::crypto
{

size_t SignDigest(HashCtx* ctx, const Hash* hash, Key* privateKey, nonstd::span<const uint8_t> tbs,
                  nonstd::span<uint8_t> signature);

bool VerifyDigest(HashCtx* ctx, const Hash* hash, Key* publicKey, nonstd::span<const uint8_t> tbs,
                  nonstd::span<const uint8_t> signature);

} // namespace snet::crypto