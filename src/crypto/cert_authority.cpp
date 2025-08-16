
#include <openssl/x509v3.h>
#include <openssl/bn.h>

#include <snet/crypto/cert_authority.hpp>
#include <snet/crypto/cert_builder.hpp>
#include <snet/crypto/cert_name_builder.hpp>

namespace snet::crypto
{

CertAuthority::CertAuthority(KeyPtr key, const std::string& name)
    : key_(std::move(key))
    , cert_(generateCert(key_.get(), key_.get(), nullptr, name))
{
}

CertAuthority::~CertAuthority() noexcept
{
}

Key* CertAuthority::getKey() const
{
    return key_.get();
}

X509Cert* CertAuthority::getCert() const
{
    return cert_.get();
}

X509CertPtr CertAuthority::sign(const std::string& name, Key* publicKey)
{
    return generateCert(publicKey, key_.get(), cert_.get(), name);
}

X509CertPtr CertAuthority::generateCert(Key* subjectKey, Key* issuerKey, X509Cert* issuerCert, const std::string& dn)
{
    CertBuilder certBuilder;

    certBuilder.setNotBefore(std::chrono::seconds(0));
    certBuilder.setNotAfter(std::chrono::hours(24));

    BigNumPtr serial(BN_new());
    if (serial)
    {
        BN_rand(serial, 64, 0, 0);
    }
    certBuilder.setSerialNumber(serial.get());

    auto name = CertNameBuilder::fromString(dn);
    certBuilder.setSubjectName(name);
    certBuilder.setPublicKey(subjectKey);

    if (subjectKey == issuerKey)
    {
        certBuilder.selfSigned(issuerKey);
        certBuilder.setVersion(CertVersion::V3);
        certBuilder.setIssuerName(name);
        certBuilder.addExtension(NID_subject_key_identifier, "hash");
        certBuilder.addExtension(NID_basic_constraints, "critical,CA:TRUE");
        certBuilder.addExtension(NID_key_usage, "critical,cRLSign,keyCertSign");
    }
    else
    {
        certBuilder.signedBy(issuerKey, issuerCert);
        certBuilder.setVersion(CertVersion::V3);
        certBuilder.setIssuerName(X509_get_issuer_name(issuerCert));
        certBuilder.addExtension(NID_authority_key_identifier, "keyid");
        certBuilder.addExtension(NID_subject_key_identifier, "hash");
    }

    return certBuilder.build();
}

} // namespace snet::crypto
