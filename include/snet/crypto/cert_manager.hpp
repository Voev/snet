#pragma once
#include <filesystem>
#include <snet/crypto/pointers.hpp>
#include <snet/utils/noncopyable.hpp>

namespace snet::crypto
{

class CertManager final : public utils::NonCopyable
{
public:
    CertManager();

    ~CertManager() noexcept;

    CertManager& useDefaultPaths();

    CertManager& addCA(Cert* cert);

    CertManager& addCRL(Crl* crl);

    CertManager& loadFile(const std::filesystem::path& path);

    CertManager& loadDirectory(const std::filesystem::path& path);

    CertManager& loadStore(std::string_view uri);

    CertManager& setLookupCRLs(X509_STORE_CTX_lookup_crls_fn cb)
    {
        X509_STORE_set_lookup_crls(store_, cb);
        return *this;
    }

    CertManager& setGetIssuer(X509_STORE_CTX_get_issuer_fn cb)
    {
        X509_STORE_set_get_issuer(store_, cb);
        return *this;
    }

    CertManager& setVerifyCallback(X509_STORE_CTX_verify_cb cb)
    {
        X509_STORE_set_verify_cb(store_, cb);
        return *this;
    }

    CertStore* certStore();

private:
    CertStorePtr store_;
};

} // namespace snet::crypto