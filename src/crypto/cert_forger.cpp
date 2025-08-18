#include <snet/crypto/cert.hpp>
#include <snet/crypto/cert_builder.hpp>
#include <snet/crypto/cert_forger.hpp>
#include <snet/crypto/asymm_key.hpp>

#include <casket/utils/exception.hpp>

using namespace snet;

namespace snet::crypto
{

CertForger::CertForger(Key* caKey, X509Cert* caCert)
    : caKey_(AsymmKey::shallowCopy(caKey))
    , caCert_(Cert::shallowCopy(caCert))
{
}

X509CertPtr CertForger::resign(Key* forgedKey, X509Cert* originCert)
{
    casket::ThrowIfFalse(originCert != nullptr, "Invalid origin certificate");

    CertBuilder builder;
    builder.signedBy(caKey_, caCert_);
    builder.setPublicKey(forgedKey);

    builder.setIssuerName(X509_get_issuer_name(originCert));
    builder.setSubjectName(X509_get_subject_name(originCert));
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

} // namespace snet::crypto
