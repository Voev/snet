#pragma once

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/store.h>
#include <openssl/cms.h>
#include <openssl/safestack.h>

#include <snet/crypto/typedefs.hpp>
#include <snet/utils/custom_unique_ptr.hpp>

namespace snet::crypto
{

struct StoreCtxDeleter
{
    void operator()(StoreCtx* ctx) const noexcept
    {
        OSSL_STORE_close(ctx);
    }
};

struct CertStackDeleter
{
    void operator()(CertStack* stack) const noexcept
    {
        sk_X509_free(stack);
    }
};

struct CertExtStackDeleter
{
    void operator()(CertExtStack* stack) const noexcept
    {
        sk_X509_EXTENSION_free(stack);
    }
};

struct CertExtOwningStackDeleter
{
    void operator()(CertExtStack* stack) const noexcept
    {
        sk_X509_EXTENSION_pop_free(stack, X509_EXTENSION_free);
    }
};

DEFINE_CUSTOM_UNIQUE_PTR(Asn1IntegerPtr, Asn1Integer, ASN1_INTEGER_free);
DEFINE_CUSTOM_UNIQUE_PTR(Asn1TimePtr, Asn1Time, ASN1_TIME_free);
DEFINE_CUSTOM_UNIQUE_PTR(Asn1OctetStringPtr, Asn1OctetString, ASN1_OCTET_STRING_free);
DEFINE_CUSTOM_UNIQUE_PTR(BigNumPtr, BigNum, BN_free);
DEFINE_CUSTOM_UNIQUE_PTR(BioPtr, Bio, BIO_free_all);
DEFINE_CUSTOM_UNIQUE_PTR(CertExtPtr, CertExt, X509_EXTENSION_free);
DEFINE_CUSTOM_UNIQUE_PTR(CertNamePtr, CertName, X509_NAME_free);
DEFINE_CUSTOM_UNIQUE_PTR(CertPtr, Cert, X509_free);
DEFINE_CUSTOM_UNIQUE_PTR(CertStorePtr, CertStore, X509_STORE_free);
DEFINE_CUSTOM_UNIQUE_PTR(CertStoreCtxPtr, CertStoreCtx, X509_STORE_CTX_free);
DEFINE_CUSTOM_UNIQUE_PTR(CsrPtr, Csr, X509_REQ_free);
DEFINE_CUSTOM_UNIQUE_PTR(CrlPtr, Crl, X509_CRL_free);
DEFINE_CUSTOM_UNIQUE_PTR(KeyCtxPtr, KeyCtx, EVP_PKEY_CTX_free);
DEFINE_CUSTOM_UNIQUE_PTR(KeyPtr, Key, EVP_PKEY_free);
DEFINE_CUSTOM_UNIQUE_PTR(HashCtxPtr, HashCtx, EVP_MD_CTX_free);
DEFINE_CUSTOM_UNIQUE_PTR(StoreInfoPtr, StoreInfo, OSSL_STORE_INFO_free);

DEFINE_CUSTOM_UNIQUE_PTR_WITH_DELETER(CertStackPtr, CertStack, CertStackDeleter);
DEFINE_CUSTOM_UNIQUE_PTR_WITH_DELETER(CertExtStackPtr, CertExtStack, CertExtStackDeleter);
DEFINE_CUSTOM_UNIQUE_PTR_WITH_DELETER(CertExtOwningStackPtr, CertExtStack,
                                      CertExtOwningStackDeleter);
DEFINE_CUSTOM_UNIQUE_PTR_WITH_DELETER(StoreCtxPtr, StoreCtx, StoreCtxDeleter);

DEFINE_CUSTOM_UNIQUE_PTR(HashPtr, Hash, EVP_MD_free);

} // namespace snet::crypto
