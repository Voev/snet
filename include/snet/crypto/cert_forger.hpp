#pragma once
#include <snet/crypto/pointers.hpp>
#include <snet/utils/noncopyable.hpp>

namespace snet::crypto
{

struct CertForger final : public utils::NonCopyable
{
public:
    CertForger(Key* caKey, Cert* caCert);

    ~CertForger() = default;

    CertForger(CertForger&&) = default;

    CertForger& operator=(CertForger&&) = default;

    KeyPtr getForgedKey();

    CertPtr resign(Cert* originCert);

private:
    KeyPtr privateKey_;
    KeyPtr caKey_;
    CertPtr caCert_;
};

} // namespace snet::crypto
