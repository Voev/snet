#pragma once
#include <openssl/x509_vfy.h>

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#define OSSL_CONST_COMPAT const
#else
#define OSSL_CONST_COMPAT
#endif

enum class CertVersion
{
    V1 = 0, ///< X509v1
    V2 = 1, ///< X509v2
    V3 = 2, ///< X509v3
};

enum class KeyType
{
    Public,
    Private
};

enum class Encoding
{
    PEM,
    DER,
};

enum class VerifyFlag
{
    CrlCheck = X509_V_FLAG_CRL_CHECK,
    CrlCheckAll = X509_V_FLAG_CRL_CHECK_ALL,
    StrictCheck = X509_V_FLAG_X509_STRICT,
    CheckSelfSigned = X509_V_FLAG_CHECK_SS_SIGNATURE,
    SearchTrustedFirst = X509_V_FLAG_TRUSTED_FIRST,
};

using Aki = struct AUTHORITY_KEYID_st;
using Asn1Integer = struct asn1_string_st;
using Asn1Object = struct asn1_object_st;
using Asn1OctetString = struct asn1_string_st;
using Asn1Time = struct asn1_string_st;
using BigNum = struct bignum_st;
using Bio = struct bio_st;
using X509Cert = struct x509_st;
using X509Attr = struct x509_attributes_st;
using X509Ext = struct X509_extension_st;
using X509Name = struct X509_name_st;
using X509Store = struct x509_store_st;
using X509StoreCtx = struct x509_store_ctx_st;
using X509V3Ctx = struct v3_ext_ctx;
using X509Req = struct X509_req_st;
using X509Crl = struct X509_crl_st;
using Hash = struct evp_md_st;
using HashCtx = struct evp_md_ctx_st;
using Key = struct evp_pkey_st;
using KeyCtx = struct evp_pkey_ctx_st;
using Cipher = struct evp_cipher_st;
using CipherCtx = struct evp_cipher_ctx_st;

using StoreCtx = struct ossl_store_ctx_st;
using StoreInfo = struct ossl_store_info_st;
using UiMethod = struct ui_method_st;

using CrlDistPoints = STACK_OF(DIST_POINT);
using AuthInfoAccess = STACK_OF(ACCESS_DESCRIPTION);

using CertStack = STACK_OF(X509);
using CertExtStack = STACK_OF(X509_EXTENSION);
using CrlStack = STACK_OF(X509_CRL);

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
using Kdf = struct evp_kdf_st;
using KdfCtx = struct evp_kdf_ctx_st;
using Mac = struct evp_mac_st;
using MacCtx = struct evp_mac_ctx_st;
using LibContext = struct ossl_lib_ctx_st;
#else
using MacCtx = struct hmac_ctx_st;
#endif