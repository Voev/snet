#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <snet/crypto/cert_verifier.hpp>
#include <snet/crypto/cert_manager.hpp>

#include <snet/crypto/error_code.hpp>
#include <snet/crypto/exception.hpp>

#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::crypto {

CertVerifier::CertVerifier(CertManager& manager)
    : ctx_(X509_STORE_CTX_new()) {
    ::utils::ThrowIfTrue(ctx_ == nullptr, "memory allocation error");
    crypto::ThrowIfFalse(0 < X509_STORE_CTX_init(ctx_, manager.certStore(), nullptr, nullptr));

    setFlag(VerifyFlag::StrictCheck);
    setFlag(VerifyFlag::CheckSelfSigned);
    setFlag(VerifyFlag::SearchTrustedFirst);
}

CertVerifier::~CertVerifier() noexcept {
}

CertVerifier& CertVerifier::setFlag(VerifyFlag flag) {
    auto param = X509_STORE_CTX_get0_param(ctx_);
    X509_VERIFY_PARAM_set_flags(param, static_cast<unsigned long>(flag));
    return *this;
}

CertVerifier& CertVerifier::clearFlag(VerifyFlag flag) {
    auto param = X509_STORE_CTX_get0_param(ctx_);
    X509_VERIFY_PARAM_clear_flags(param, static_cast<unsigned long>(flag));
    return *this;
}

std::error_code CertVerifier::verify(Cert* cert) noexcept {

    X509_STORE_CTX_set_cert(ctx_, cert);
    if (!X509_verify_cert(ctx_)) {
        return verify::MakeErrorCode(static_cast<verify::Error>(X509_STORE_CTX_get_error(ctx_)));
    }

    return verify::MakeErrorCode(verify::Error::No);
}

} // namespace snet::crypto