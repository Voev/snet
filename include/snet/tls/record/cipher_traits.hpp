#pragma once
#include <string>
#include <openssl/evp.h>
#include <snet/tls/types.hpp>
#include <snet/tls/version.hpp>

namespace snet::tls
{

struct CipherTraits
{
    ProtocolVersion version;
    std::string cipherName;
    std::string digestName;
    std::size_t blockSize{0};
    bool aead{false};
    bool encryptThenMac{false};
};

inline size_t GetTagLength(EVP_CIPHER_CTX* ctx)
{
    if (EVP_CIPHER_CTX_get_mode(ctx) == EVP_CIPH_CCM_MODE)
    {
        return EVP_CCM_TLS_TAG_LEN;
    }
    return EVP_CIPHER_CTX_get_tag_length(ctx);
}

} // namespace snet::tls