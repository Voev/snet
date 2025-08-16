#pragma once
#include <snet/crypto/pointers.hpp>
#include <casket/utils/noncopyable.hpp>

namespace snet::crypto
{

struct CertForger final : public casket::NonCopyable
{
public:
    CertForger(Key* caKey, X509Cert* caCert);

    ~CertForger() = default;

    CertForger(CertForger&&) = default;

    CertForger& operator=(CertForger&&) = default;

    X509CertPtr resign(Key* forgedKey, X509Cert* originCert);

private:
    KeyPtr caKey_;
    X509CertPtr caCert_;
};

} // namespace snet::crypto
