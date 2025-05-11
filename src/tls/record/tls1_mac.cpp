#include <array>
#include <openssl/evp.h>
#include <openssl/core_names.h>

#include <snet/tls/record/tls1_mac.hpp>
#include <snet/tls/cipher_suite_manager.hpp>

#include <snet/crypto/pointers.hpp>
#include <snet/crypto/exception.hpp>

#include <snet/utils/data_reader.hpp>

#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::tls::v1
{

void checkTls1Mac(const CipherTraits& traits, uint64_t seq, RecordType recordType,
                  std::span<const uint8_t> macKey, std::span<const uint8_t> content,
                  std::span<const uint8_t> expectedMac, std::span<const uint8_t> iv)
{
    std::array<uint8_t, 13> meta;
    utils::store_be(seq, meta.data());
    meta[8] = static_cast<uint8_t>(recordType);
    meta[9] = traits.version.majorVersion();
    meta[10] = traits.version.minorVersion();
    uint16_t s = content.size() + iv.size();
    meta[11] = utils::get_byte<0>(s);
    meta[12] = utils::get_byte<1>(s);

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 const_cast<char*>(traits.digestName.c_str()), 0);
    params[1] = OSSL_PARAM_construct_end();

    auto mac = CipherSuiteManager::getInstance().fetchMac("HMAC");

    crypto::MacCtxPtr ctx(EVP_MAC_CTX_new(mac));
    crypto::ThrowIfTrue(ctx == nullptr);

    crypto::ThrowIfFalse(0 < EVP_MAC_CTX_set_params(ctx, params));
    crypto::ThrowIfFalse(0 < EVP_MAC_init(ctx, macKey.data(), macKey.size(), nullptr));
    crypto::ThrowIfFalse(0 < EVP_MAC_update(ctx, meta.data(), meta.size()));

    if (!iv.empty())
    {
        crypto::ThrowIfFalse(0 < EVP_MAC_update(ctx, iv.data(), iv.size()));
    }

    crypto::ThrowIfFalse(0 < EVP_MAC_update(ctx, content.data(), content.size()));

    size_t actualMacSize{EVP_MAX_MD_SIZE};
    std::vector<uint8_t> actualMac(actualMacSize);
    crypto::ThrowIfFalse(0 < EVP_MAC_final(ctx, actualMac.data(), &actualMacSize, actualMacSize));

    actualMac.resize(actualMacSize);

    ::utils::ThrowIfFalse(std::equal(expectedMac.begin(), expectedMac.end(), actualMac.begin()),
                          "Bad record MAC");
}

void checkSsl3Mac(const CipherTraits& traits, uint64_t seq, RecordType recordType,
                  std::span<const uint8_t> macKey, std::span<const uint8_t> content,
                  std::span<const uint8_t> expectedMac)
{
    unsigned int actualMacSize{EVP_MAX_MD_SIZE};
    std::vector<uint8_t> actualMac(actualMacSize);

    crypto::HashCtxPtr ctx(EVP_MD_CTX_new());
    crypto::ThrowIfFalse(ctx != nullptr);

    auto md = CipherSuiteManager::getInstance().fetchDigest(traits.digestName);
    crypto::ThrowIfFalse(md != nullptr);

    int pad_ct = EVP_MD_is_a(md, "SHA1") > 0 ? 40 : 48;

    crypto::ThrowIfFalse(0 < EVP_DigestInit(ctx, md));
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, macKey.data(), macKey.size()));

    uint8_t buf[64];
    memset(buf, 0x36, pad_ct);
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, buf, pad_ct));

    std::array<uint8_t, 11> meta;
    utils::store_be(seq, meta.data());
    meta[8] = static_cast<uint8_t>(recordType);
    uint16_t s = content.size();
    meta[9] = utils::get_byte<0>(s);
    meta[10] = utils::get_byte<1>(s);

    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, meta.data(), meta.size()));
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, content.data(), content.size()));
    crypto::ThrowIfFalse(0 < EVP_DigestFinal(ctx, actualMac.data(), &actualMacSize));

    actualMac.resize(actualMacSize);

    crypto::ThrowIfFalse(0 < EVP_DigestInit(ctx, md));
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, macKey.data(), macKey.size()));

    memset(buf, 0x5c, pad_ct);
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, buf, pad_ct));
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, actualMac.data(), actualMacSize));
    crypto::ThrowIfFalse(0 < EVP_DigestFinal(ctx, actualMac.data(), &actualMacSize));

    actualMac.resize(actualMacSize);

    ::utils::ThrowIfFalse(std::equal(expectedMac.begin(), expectedMac.end(), actualMac.begin()),
                          "Bad record MAC");
}

} // namespace snet::tls::v1