#pragma once
#include <snet/crypto/pointers.hpp>
#include <casket/utils/noncopyable.hpp>

namespace snet::crypto
{

class CertAuthority final : public casket::NonCopyable
{
public:
    CertAuthority(KeyPtr key, const std::string& name);

    ~CertAuthority() noexcept;

    Key* getKey() const;

    X509Cert* getCert() const;

    X509CertPtr sign(const std::string& name, Key* publicKey);

    CertAuthority(CertAuthority&& other) = default;

    CertAuthority& operator=(CertAuthority&& other) = default;

private:
    static X509CertPtr generateCert(Key* subjectKey, Key* issuerKey, X509Cert* issuerCert, const std::string& dn);

private:
    KeyPtr key_;
    X509CertPtr cert_;
};

} // namespace snet::crypto
