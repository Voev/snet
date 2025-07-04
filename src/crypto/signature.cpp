#include <openssl/evp.h>
#include <snet/crypto/signature.hpp>
#include <snet/crypto/exception.hpp>
#include <snet/crypto/crypto_manager.hpp>

namespace snet::crypto
{

size_t SignDigest(HashCtx* ctx, const Hash* hash, Key* privateKey, nonstd::span<const uint8_t> tbs,
                  nonstd::span<uint8_t> signature)
{
    size_t signatureSize{0};
    if (signature.empty())
    {
        ThrowIfFalse(0 < EVP_DigestSignInit(ctx, nullptr, hash, nullptr, privateKey));
        ThrowIfFalse(0 < EVP_DigestSign(ctx, nullptr, &signatureSize, tbs.data(), tbs.size()));
    }
    else
    {
        ThrowIfFalse(signatureSize == signature.size(), "invalid signature buffer size");
        ThrowIfFalse(0 < EVP_DigestSign(ctx, signature.data(), &signatureSize, tbs.data(), tbs.size()));
    }
    return signatureSize;
}

bool VerifyDigest(HashCtx* ctx, const Hash* hash, Key* publicKey, nonstd::span<const uint8_t> tbs,
                  nonstd::span<const uint8_t> signature)
{
    ThrowIfFalse(0 < EVP_DigestVerifyInit(ctx, nullptr, hash, nullptr, publicKey));

    /// @todo: set PKEY parameters if need

    return 0 < EVP_DigestVerify(ctx, signature.data(), signature.size(), tbs.data(), tbs.size());
}

} // namespace snet::crypto