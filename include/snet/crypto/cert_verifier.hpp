#pragma once
#include <system_error>
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/cert_manager.hpp>

namespace snet::crypto
{

class CertVerifier final : public casket::NonCopyable
{
public:
    explicit CertVerifier(CertManager& manager);

    ~CertVerifier() noexcept;

    CertVerifier& setFlag(VerifyFlag flag);

    CertVerifier& clearFlag(VerifyFlag flag);

    std::error_code verify(X509Cert* cert) noexcept;

private:
    X509StoreCtxPtr ctx_;
};

} // namespace snet::crypto