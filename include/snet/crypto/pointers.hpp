#pragma once

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/store.h>
#include <openssl/cms.h>
#include <openssl/safestack.h>

#include <openssl/kdf.h>

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

struct CertStack0Deleter
{
    void operator()(CertStack* stack) const noexcept
    {
        sk_X509_free(stack);
    }
};

struct CertStack1Deleter
{
    void operator()(CertStack* stack) const noexcept
    {
        sk_X509_pop_free(stack, X509_free);
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

struct CrlStackDeleter
{
    void operator()(CrlStack* stack) const noexcept
    {
        sk_X509_CRL_free(stack);
    }
};

struct CrlOwningStackDeleter
{
    void operator()(CrlStack* stack) const noexcept
    {
        sk_X509_CRL_pop_free(stack, X509_CRL_free);
    }
};

DEFINE_CUSTOM_UNIQUE_PTR(Asn1IntegerPtr, Asn1Integer, ASN1_INTEGER_free);
DEFINE_CUSTOM_UNIQUE_PTR(Asn1TimePtr, Asn1Time, ASN1_TIME_free);
DEFINE_CUSTOM_UNIQUE_PTR(Asn1OctetStringPtr, Asn1OctetString, ASN1_OCTET_STRING_free);

DEFINE_CUSTOM_UNIQUE_PTR(BigNumPtr, BigNum, BN_free);
DEFINE_CUSTOM_UNIQUE_PTR(BioPtr, Bio, BIO_free_all);

DEFINE_CUSTOM_UNIQUE_PTR(X509CertPtr, X509Cert, X509_free);
DEFINE_CUSTOM_UNIQUE_PTR(X509ReqPtr, X509Req, X509_REQ_free);
DEFINE_CUSTOM_UNIQUE_PTR(X509CrlPtr, X509Crl, X509_CRL_free);
DEFINE_CUSTOM_UNIQUE_PTR(X509ExtPtr, X509Ext, X509_EXTENSION_free);
DEFINE_CUSTOM_UNIQUE_PTR(X509NamePtr, X509Name, X509_NAME_free);
DEFINE_CUSTOM_UNIQUE_PTR(X509StorePtr, X509Store, X509_STORE_free);
DEFINE_CUSTOM_UNIQUE_PTR(X509StoreCtxPtr, X509StoreCtx, X509_STORE_CTX_free);

DEFINE_CUSTOM_UNIQUE_PTR(StoreInfoPtr, StoreInfo, OSSL_STORE_INFO_free);

DEFINE_CUSTOM_UNIQUE_PTR(KeyPtr, Key, EVP_PKEY_free);
DEFINE_CUSTOM_UNIQUE_PTR(KeyCtxPtr, KeyCtx, EVP_PKEY_CTX_free);
DEFINE_CUSTOM_UNIQUE_PTR(HashPtr, Hash, EVP_MD_free);
DEFINE_CUSTOM_UNIQUE_PTR(HashCtxPtr, HashCtx, EVP_MD_CTX_free);
DEFINE_CUSTOM_UNIQUE_PTR(CipherPtr, Cipher, EVP_CIPHER_free);
DEFINE_CUSTOM_UNIQUE_PTR(CipherCtxPtr, CipherCtx, EVP_CIPHER_CTX_free);
DEFINE_CUSTOM_UNIQUE_PTR(KdfPtr, Kdf, EVP_KDF_free);
DEFINE_CUSTOM_UNIQUE_PTR(KdfCtxPtr, KdfCtx, EVP_KDF_CTX_free);
DEFINE_CUSTOM_UNIQUE_PTR(MacPtr, Mac, EVP_MAC_free);
DEFINE_CUSTOM_UNIQUE_PTR(MacCtxPtr, MacCtx, EVP_MAC_CTX_free);

DEFINE_CUSTOM_UNIQUE_PTR(CrlDistPointsPtr, CrlDistPoints, CRL_DIST_POINTS_free);
DEFINE_CUSTOM_UNIQUE_PTR(AuthInfoAccessPtr, AuthInfoAccess, AUTHORITY_INFO_ACCESS_free);

DEFINE_CUSTOM_UNIQUE_PTR_WITH_DELETER(CertStack0Ptr, CertStack, CertStack0Deleter);
DEFINE_CUSTOM_UNIQUE_PTR_WITH_DELETER(CertStack1Ptr, CertStack, CertStack1Deleter);

DEFINE_CUSTOM_UNIQUE_PTR_WITH_DELETER(CertExtStackPtr, CertExtStack, CertExtStackDeleter);
DEFINE_CUSTOM_UNIQUE_PTR_WITH_DELETER(CertExtOwningStackPtr, CertExtStack,
                                      CertExtOwningStackDeleter);
DEFINE_CUSTOM_UNIQUE_PTR_WITH_DELETER(CrlStackPtr, CrlStack, CrlStackDeleter);
DEFINE_CUSTOM_UNIQUE_PTR_WITH_DELETER(CrlOwningStackPtr, CrlStack, CrlOwningStackDeleter);
DEFINE_CUSTOM_UNIQUE_PTR_WITH_DELETER(StoreCtxPtr, StoreCtx, StoreCtxDeleter);

} // namespace snet::crypto
