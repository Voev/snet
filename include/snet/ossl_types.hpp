#pragma once
#include <memory>
#include <openssl/bio.h>

namespace ossl
{

template <typename T, void (*f)(T*)> struct static_function_deleter
{
    void operator()(T* t) const
    {
        f(t);
    }
};

#define OSSL_DEFINE_PTR_TYPE(alias, object, deleter)                           \
    using alias##Deleter = static_function_deleter<object, &deleter>;          \
    using alias##Ptr = std::unique_ptr<object, alias##Deleter>

OSSL_DEFINE_PTR_TYPE(Bio, BIO, BIO_free_all);
OSSL_DEFINE_PTR_TYPE(BioAddr, BIO_ADDR, BIO_ADDR_free);

} // namespace ossl
