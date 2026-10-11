#pragma once
#include <memory>
#include <snet/crypto/pointers.hpp>
#include <casket/nonstd/string_view.hpp>
#include <casket/utils/singleton.hpp>

namespace snet::crypto
{

class CryptoManager final : casket::Singleton<CryptoManager>
{
private:
    CryptoManager();

public:

    static CryptoManager& getInstance();

    ~CryptoManager() noexcept;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)

    crypto::KdfPtr fetchKdf(nonstd::string_view algorithm);

    crypto::MacPtr fetchMac(nonstd::string_view algorithm);

#endif // (OPENSSL_VERSION_NUMBER >= 0x30000000L)

    crypto::HashAlg fetchDigest(nonstd::string_view algorithm);

    crypto::CipherAlg fetchCipher(nonstd::string_view algorithm);

    KeyCtxPtr createKeyContext(nonstd::string_view algorithm);

    KeyCtxPtr createKeyContext(Key* key);

private:
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)

    struct Impl;
    std::unique_ptr<Impl> impl_;

#endif // (OPENSSL_VERSION_NUMBER >= 0x30000000L)
};

} // namespace snet::tls