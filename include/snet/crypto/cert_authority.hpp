#pragma once
#include <snet/crypto/pointers.hpp>
#include <casket/utils/noncopyable.hpp>

namespace snet::crypto
{

class CertAuthority final : public casket::NonCopyable
{
public:
    CertAuthority(const std::string& name);

    ~CertAuthority() noexcept;

    Key* getKey() const;

    Cert* getCert() const;

    CertPtr sign(const std::string& name, Key* publicKey);

    CertAuthority(CertAuthority&& other) = default;

    CertAuthority& operator=(CertAuthority&& other) = default;

private:
    static CertPtr generateCert(Key* subjectKey, Key* issuerKey, Cert* issuerCert,
                                const std::string& dn);

private:
    KeyPtr key_;
    CertPtr cert_;
};

} // namespace snet::crypto
