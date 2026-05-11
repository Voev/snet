
#include <openssl/x509v3.h>
#include <openssl/bn.h>

#include <snet/crypto/cert_authority.hpp>
#include <snet/crypto/cert_builder.hpp>
#include <snet/crypto/cert_name_builder.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::crypto
{

CertAuthority::CertAuthority(KeyPtr key, const std::string& name)
    : key_(std::move(key))
    , cert_(generateCert(key_.get(), key_.get(), nullptr, name))
{
}

CertAuthority::CertAuthority(KeyPtr key, X509CertPtr cert)
    : key_(std::move(key))
    , cert_(std::move(cert))
{
    ThrowIfFalse(0 < X509_check_private_key(cert_, key_));
    ThrowIfFalse(0 < X509_check_ca(cert_), "Certificate is not CA");
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

X509CertPtr CertAuthority::resign(Key* forgedKey, X509Cert* originCert)
{
    CertBuilder builder;
    builder.signedBy(key_, cert_);
    builder.setPublicKey(forgedKey);

    builder.setSubjectName(X509_get_subject_name(originCert));
    builder.setIssuerName(X509_get_issuer_name(cert_));

    builder.setNotBefore(X509_get0_notBefore(originCert));
    builder.setNotAfter(X509_get0_notAfter(originCert));

    if (X509_get_ext_count(originCert) > 0)
    {
        builder.setVersion(CertVersion::V3);
        auto extensions = X509_get0_extensions(originCert);
        const auto subjectAltName = OBJ_nid2obj(NID_subject_alt_name);
        const auto extKeyUsage = OBJ_nid2obj(NID_ext_key_usage);
        const auto basicConstrs = OBJ_nid2obj(NID_basic_constraints);
        const auto subjectKeyId = OBJ_nid2obj(NID_subject_key_identifier);
        const auto authKeyId = OBJ_nid2obj(NID_authority_key_identifier);

        for (int i = 0; i < sk_X509_EXTENSION_num(extensions); ++i)
        {
            X509_EXTENSION* extension = sk_X509_EXTENSION_value(extensions, i);
            ASN1_OBJECT* obj = X509_EXTENSION_get_object(extension);

            if (OBJ_cmp(obj, subjectAltName) == 0)
            {
                builder.addExtension(extension);
            }
            else if (OBJ_cmp(obj, extKeyUsage) == 0)
            {
                builder.addExtension(extension);
            }
            else if (OBJ_cmp(obj, basicConstrs) == 0)
            {
                builder.addExtension(extension);
            }
            else if (OBJ_cmp(obj, subjectKeyId) == 0)
            {
                builder.addExtension(NID_subject_key_identifier, "hash");
            }
            else if (OBJ_cmp(obj, authKeyId) == 0)
            {
                builder.addExtension(NID_authority_key_identifier, "keyid, issuer");
            }
        }
    }
    else
    {
        builder.setVersion(CertVersion::V2);
    }

    return builder.build();
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
