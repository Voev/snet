#pragma once
#include <system_error>
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/cert_manager.hpp>

namespace snet::crypto {

class CertVerifier final : public utils::NonCopyable {
public:
    explicit CertVerifier(CertManager& manager);

    ~CertVerifier() noexcept;

    CertVerifier& setFlag(VerifyFlag flag);

    CertVerifier& clearFlag(VerifyFlag flag);

    std::error_code verify(Cert* cert) noexcept;

private:
    CertStoreCtxPtr ctx_;
};

} // namespace snet::crypto