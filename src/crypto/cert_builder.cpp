#include <limits>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <snet/crypto/exception.hpp>
#include <snet/crypto/error_code.hpp>

#include <snet/crypto/cert.hpp>
#include <snet/crypto/cert_builder.hpp>
#include <snet/crypto/cert_name_builder.hpp>

using namespace snet;

namespace
{

crypto::BigNumPtr randBigNum(size_t bits = 64)
{
    crypto::BigNumPtr ret(BN_new());
    crypto::ThrowIfTrue(ret == nullptr);

    constexpr auto limit = std::numeric_limits<int>::max();
    crypto::ThrowIfFalse(0 < BN_rand(ret, (bits > limit ? limit : static_cast<int>(bits)), 0, 0));
    return ret;
}

crypto::Asn1IntegerPtr convertToAsn1(const BigNum* num)
{
    crypto::Asn1IntegerPtr ret(ASN1_INTEGER_new());
    crypto::ThrowIfTrue(ret == nullptr);
    crypto::ThrowIfFalse(BN_to_ASN1_INTEGER(num, ret));
    return ret;
}

} // namespace

namespace snet::crypto
{

struct CertBuilder::Impl
{
    X509CertPtr cert;
    X509V3Ctx ctx;
    KeyPtr signingKey;
    X509CertPtr issuerCert;

    Impl()
    {
        reset();
    }

    void reset()
    {
        cert.reset(X509_new());
        crypto::ThrowIfTrue(cert == nullptr);

        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, nullptr, nullptr, nullptr, nullptr, X509V3_CTX_REPLACE);

        signingKey.reset();
        issuerCert.reset();
    }
};

CertBuilder::CertBuilder()
    : impl_(std::make_unique<CertBuilder::Impl>())
{
}

CertBuilder::~CertBuilder() noexcept
{
}

void CertBuilder::reset()
{
    impl_->reset();
}

CertBuilder& CertBuilder::setVersion(CertVersion version)
{
    crypto::ThrowIfFalse(X509_set_version(impl_->cert, static_cast<long>(version)));
    return *this;
}

CertBuilder& CertBuilder::setSubjectName(OSSL_CONST_COMPAT X509Name* name)
{
    crypto::ThrowIfFalse(X509_set_subject_name(impl_->cert, name));
    return *this;
}

CertBuilder& CertBuilder::setSubjectName(const std::string& name)
{
    auto decodedName = CertNameBuilder::fromString(name);
    return setSubjectName(decodedName);
}

CertBuilder& CertBuilder::setIssuerName(OSSL_CONST_COMPAT X509Name* name)
{
    crypto::ThrowIfFalse(X509_set_issuer_name(impl_->cert, name));
    return *this;
}

CertBuilder& CertBuilder::setIssuerName(const std::string& name)
{
    auto decodedName = CertNameBuilder::fromString(name);
    return setIssuerName(decodedName);
}

CertBuilder& CertBuilder::setPublicKey(Key* subjectPublicKey)
{
    crypto::ThrowIfFalse(X509_set_pubkey(impl_->cert, subjectPublicKey));
    return *this;
}

CertBuilder& CertBuilder::setSerialNumber(const Asn1Integer* serialNumber)
{
    crypto::ThrowIfFalse(X509_set_serialNumber(impl_->cert, const_cast<Asn1Integer*>(serialNumber)));
    return *this;
}

CertBuilder& CertBuilder::setSerialNumber(const BigNum* serialNumber)
{
    crypto::ThrowIfFalse(BN_to_ASN1_INTEGER(serialNumber, X509_get_serialNumber(impl_->cert)));
    return *this;
}

CertBuilder& CertBuilder::setNotBefore(const Asn1Time* time)
{
    crypto::ThrowIfFalse(X509_set1_notBefore(impl_->cert, time));
    return *this;
}

CertBuilder& CertBuilder::setNotBefore(std::chrono::seconds offsetSec)
{
    crypto::ThrowIfFalse(X509_time_adj(X509_getm_notBefore(impl_->cert), offsetSec.count(), nullptr));
    return *this;
}

CertBuilder& CertBuilder::setNotBefore(nonstd::chrono_years offsetYears)
{
    return setNotBefore(std::chrono::duration_cast<std::chrono::seconds>(offsetYears));
}

CertBuilder& CertBuilder::setNotAfter(const Asn1Time* time)
{
    crypto::ThrowIfFalse(X509_set1_notAfter(impl_->cert, time));
    return *this;
}

CertBuilder& CertBuilder::setNotAfter(std::chrono::seconds offsetSec)
{
    crypto::ThrowIfFalse(X509_time_adj(X509_getm_notAfter(impl_->cert), offsetSec.count(), nullptr));
    return *this;
}

CertBuilder& CertBuilder::setNotAfter(nonstd::chrono_years offsetYears)
{
    return setNotAfter(std::chrono::duration_cast<std::chrono::seconds>(offsetYears));
}

CertBuilder& CertBuilder::addExtension(X509Ext* ext)
{
    crypto::ThrowIfFalse(X509_add_ext(impl_->cert, ext, -1));
    return *this;
}

CertBuilder& CertBuilder::addExtension(int extNid, std::string_view value)
{
    X509ExtPtr ext(X509V3_EXT_conf_nid(nullptr, &impl_->ctx, extNid, value.data()));
    crypto::ThrowIfTrue(ext == nullptr);
    return addExtension(ext);
}

CertBuilder& CertBuilder::addExtension(std::string_view name, std::string_view value)
{
    X509ExtPtr ext(X509V3_EXT_conf(nullptr, &impl_->ctx, name.data(), value.data()));
    crypto::ThrowIfTrue(ext == nullptr);
    return addExtension(ext);
}

CertBuilder& CertBuilder::signedBy(Key* issuerPrivateKey, X509Cert* issuerCert)
{
    OPENSSL_assert(0 < X509_check_private_key(issuerCert, issuerPrivateKey));

    crypto::ThrowIfFalse(EVP_PKEY_up_ref(issuerPrivateKey));
    impl_->signingKey = KeyPtr(issuerPrivateKey);

    crypto::ThrowIfFalse(X509_up_ref(issuerCert));
    impl_->issuerCert = X509CertPtr(issuerCert);

    X509V3_set_ctx(&impl_->ctx, impl_->issuerCert, impl_->cert, nullptr, nullptr, X509V3_CTX_REPLACE);
    return *this;
}

CertBuilder& CertBuilder::selfSigned(Key* subjectPrivateKey)
{
    crypto::ThrowIfFalse(EVP_PKEY_up_ref(subjectPrivateKey));
    impl_->signingKey = KeyPtr(subjectPrivateKey);

    X509V3_set_ctx(&impl_->ctx, impl_->cert, impl_->cert, nullptr, nullptr, X509V3_CTX_REPLACE);
    return *this;
}

X509CertPtr CertBuilder::build()
{
    crypto::ThrowIfTrue(impl_->signingKey == nullptr, "signing key not specified");

    auto serial = Cert::serialNumber(impl_->cert);
    if (BN_is_zero(serial))
    {
        auto n = ::randBigNum();
        auto s = ::convertToAsn1(n);
        setSerialNumber(s);
    }

    int mdNid{NID_undef};
    crypto::ThrowIfFalse(EVP_PKEY_get_default_digest_nid(impl_->signingKey, &mdNid));

    const EVP_MD* md = EVP_get_digestbynid(mdNid);
    crypto::ThrowIfTrue(md == nullptr);
    crypto::ThrowIfFalse(X509_sign(impl_->cert, impl_->signingKey, md));

    auto result = std::move(impl_->cert);
    reset();

    return result;
}

} // namespace snet::crypto
