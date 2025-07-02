#pragma once
#include <memory>
#include <string_view>
#include <snet/crypto/pointers.hpp>
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

    crypto::KdfPtr fetchKdf(std::string_view algorithm);

    crypto::MacPtr fetchMac(std::string_view algorithm);

    crypto::HashPtr fetchDigest(std::string_view algorithm);

    crypto::CipherPtr fetchCipher(std::string_view algorithm);

    KeyCtxPtr createKeyContext(std::string_view algorithm);

    KeyCtxPtr createKeyContext(Key* key);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace snet::tls