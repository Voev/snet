#include <limits>
#include <memory>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <snet/crypto/exception.hpp>
#include <snet/crypto/error_code.hpp>

#include <snet/crypto/cert_req_builder.hpp>
#include <snet/crypto/cert_name_builder.hpp>

using namespace snet;

namespace snet::crypto
{

struct CertReqBuilder::Impl
{
    X509ReqPtr req;
    X509V3Ctx ctx;
    KeyPtr signingKey;
    CertExtOwningStackPtr extensions;

    Impl()
    {
        reset();
    }

    void reset()
    {
        req.reset(X509_REQ_new());
        crypto::ThrowIfTrue(req == nullptr);

        extensions.reset(sk_X509_EXTENSION_new_null());
        crypto::ThrowIfTrue(extensions == nullptr);

        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, nullptr, nullptr, nullptr, nullptr, X509V3_CTX_REPLACE);

        signingKey.reset();
    }
};

CertReqBuilder::CertReqBuilder()
    : impl_(std::make_unique<CertReqBuilder::Impl>())
{
}

CertReqBuilder::~CertReqBuilder() noexcept
{
}

void CertReqBuilder::reset()
{
    impl_->reset();
}

CertReqBuilder& CertReqBuilder::setVersion(CertReqVersion version)
{
    crypto::ThrowIfFalse(X509_REQ_set_version(impl_->req, static_cast<long>(version)));
    return *this;
}

CertReqBuilder& CertReqBuilder::setSubjectName(OSSL_CONST_COMPAT X509Name* name)
{
    crypto::ThrowIfFalse(X509_REQ_set_subject_name(impl_->req, name));
    return *this;
}

CertReqBuilder& CertReqBuilder::setSubjectName(const std::string& name)
{
    auto decodedName = CertNameBuilder::fromString(name);
    return setSubjectName(decodedName);
}

CertReqBuilder& CertReqBuilder::setPublicKey(Key* subjectPublicKey)
{
    crypto::ThrowIfFalse(X509_REQ_set_pubkey(impl_->req, subjectPublicKey));
    return *this;
}

CertReqBuilder& CertReqBuilder::addExtension(X509Ext* extension)
{
    X509ExtPtr dup{X509_EXTENSION_dup(extension)};
    crypto::ThrowIfTrue(dup == nullptr, "allocation error");

    crypto::ThrowIfFalse(0 < sk_X509_EXTENSION_push(impl_->extensions, dup));
    dup.release();
    return *this;
}

CertReqBuilder& CertReqBuilder::addExtension(int extNid, nonstd::string_view value)
{
    X509ExtPtr ext(X509V3_EXT_conf_nid(nullptr, &impl_->ctx, extNid, value.data()));
    return addExtension(ext);
}

CertReqBuilder& CertReqBuilder::addExtension(nonstd::string_view name, nonstd::string_view value)
{
    X509ExtPtr ext(X509V3_EXT_conf(nullptr, &impl_->ctx, name.data(), value.data()));
    return addExtension(ext);
}

CertReqBuilder& CertReqBuilder::signWith(Key* privateKey)
{
    crypto::ThrowIfFalse(EVP_PKEY_up_ref(privateKey));
    impl_->signingKey = KeyPtr(privateKey);

    X509V3_set_ctx(&impl_->ctx, nullptr, nullptr, impl_->req, nullptr, X509V3_CTX_REPLACE);
    return *this;
}

X509ReqPtr CertReqBuilder::build()
{
    crypto::ThrowIfTrue(impl_->signingKey == nullptr, "signing key not specified");

    crypto::ThrowIfTrue(X509_REQ_get_pubkey(impl_->req) == nullptr, "public key not specified");

    if (sk_X509_EXTENSION_num(impl_->extensions.get()) > 0)
    {
        crypto::ThrowIfFalse(X509_REQ_add_extensions(impl_->req, impl_->extensions));
    }

    int mdNid{NID_undef};
    crypto::ThrowIfFalse(EVP_PKEY_get_default_digest_nid(impl_->signingKey, &mdNid));

    const EVP_MD* md = EVP_get_digestbynid(mdNid);
    crypto::ThrowIfTrue(md == nullptr);
    crypto::ThrowIfFalse(X509_REQ_sign(impl_->req, impl_->signingKey, md));

    auto result = std::move(impl_->req);
    reset();

    return result;
}

} // namespace snet::crypto