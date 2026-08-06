#pragma once
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::crypto
{

class Crl final
{
public:
    static inline X509CrlPtr shallowCopy(X509Crl* crl)
    {
        if (crl)
        {
            crypto::ThrowIfFalse(0 < X509_CRL_up_ref(crl));
            return X509CrlPtr{crl};
        }
        return nullptr;
    }

    static inline X509CrlPtr deepCopy(X509Crl* crl)
    {
        return X509CrlPtr{X509_CRL_dup(crl)};
    }

};

} // namespace snet::crypto