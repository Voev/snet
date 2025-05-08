#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/safestack.h>
#include <openssl/ocsp.h>

#include <casket/opt/option_parser.hpp>

#include <snet/cli/command_dispatcher.hpp>

#include <snet/crypto/cert.hpp>
#include <snet/crypto/cert_verifier.hpp>

using namespace casket;

static const char* get_dp_url(DIST_POINT* dp)
{
    GENERAL_NAMES* gens;
    GENERAL_NAME* gen;
    int i, gtype;
    ASN1_STRING* uri;
    if (!dp->distpoint || dp->distpoint->type != 0)
        return NULL;
    gens = dp->distpoint->name.fullname;
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++)
    {
        gen = sk_GENERAL_NAME_value(gens, i);
        uri = (ASN1_STRING*)GENERAL_NAME_get0_value(gen, &gtype);
        if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6)
        {
            const char* uptr = (const char*)ASN1_STRING_get0_data(uri);
            return uptr;
        }
    }
    return NULL;
}

/*
 * Look through a CRLDP structure and attempt to find an http URL to
 * downloads a CRL from.
 */
X509_CRL* load_crl(const char* uri)
{
    return X509_CRL_load_http(uri, NULL, NULL, 0 /* timeout */);
}

static X509_CRL* load_crl_crldp(STACK_OF(DIST_POINT) * crldp)
{
    int i;
    const char* urlptr = NULL;
    for (i = 0; i < sk_DIST_POINT_num(crldp); i++)
    {
        DIST_POINT* dp = sk_DIST_POINT_value(crldp, i);
        urlptr = get_dp_url(dp);
        if (urlptr != NULL)
            return load_crl(urlptr);
    }
    return NULL;
}

static STACK_OF(X509_CRL) * crls_http_cb(const X509_STORE_CTX* ctx, const X509_NAME* nm)
{
    (void)nm;
    X509* x;
    STACK_OF(X509_CRL)* crls = NULL;
    X509_CRL* crl;
    STACK_OF(DIST_POINT) * crldp;

    crls = sk_X509_CRL_new_null();
    if (!crls)
        return NULL;
    x = X509_STORE_CTX_get_current_cert(ctx);
    crldp = (STACK_OF(DIST_POINT)*)X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
    crl = load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (!crl)
    {
        sk_X509_CRL_free(crls);
        return X509_STORE_CTX_get1_crls(ctx, nm);
    }
    sk_X509_CRL_push(crls, crl);
    /* Try to download delta CRL */
    crldp = (STACK_OF(DIST_POINT)*)X509_get_ext_d2i(x, NID_freshest_crl, NULL, NULL);
    crl = load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (crl)
        sk_X509_CRL_push(crls, crl);
    return crls;
}

static int append_ia5(STACK_OF(OPENSSL_STRING) * *sk, const ASN1_IA5STRING* email)
{
    char* emtmp;

    /* First some sanity checks */
    if (email->type != V_ASN1_IA5STRING)
        return 1;
    if (email->data == NULL || email->length == 0)
        return 1;
    if (memchr(email->data, 0, email->length) != NULL)
        return 1;
    if (*sk == NULL)
        *sk = (STACK_OF(OPENSSL_STRING)*)sk_OPENSSL_STRING_new_null();
    if (*sk == NULL)
        return 0;

    emtmp = OPENSSL_strndup((char*)email->data, email->length);
    if (emtmp == NULL)
    {
        X509_email_free(*sk);
        *sk = NULL;
        return 0;
    }

    if (!sk_OPENSSL_STRING_push(*sk, emtmp))
    {
        OPENSSL_free(emtmp); /* free on push failure */
        X509_email_free(*sk);
        *sk = NULL;
        return 0;
    }
    return 1;
}

STACK_OF(OPENSSL_STRING) * X509_get1_issuers(X509* x)
{
    AUTHORITY_INFO_ACCESS* info;
    STACK_OF(OPENSSL_STRING)* ret = NULL;
    int i;

    info = (AUTHORITY_INFO_ACCESS*)X509_get_ext_d2i(x, NID_info_access, NULL, NULL);
    if (!info)
        return NULL;
    for (i = 0; i < sk_ACCESS_DESCRIPTION_num(info); i++)
    {
        ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(info, i);
        if (OBJ_obj2nid(ad->method) == NID_ad_ca_issuers)
        {
            if (ad->location->type == GEN_URI)
            {
                if (!append_ia5(&ret, ad->location->d.uniformResourceIdentifier))
                    break;
            }
        }
    }
    AUTHORITY_INFO_ACCESS_free(info);
    return ret;
}

static int download_cert_http(X509 **issuer, X509 *x)
{
    auto aia = X509_get1_issuers(x);
    for(int i = 0; i < sk_OPENSSL_STRING_num(aia); ++i)
    {
        auto a = sk_OPENSSL_STRING_value(aia, i);
        X509* cert = X509_load_http(a, NULL, NULL, 0);
        if (cert)
        {
            *issuer = X509_dup(cert);
            return 1;
        }
    }

    return 0;
}

static int get_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x)
{
    int ret = X509_STORE_CTX_get1_issuer(issuer, ctx, x);
    if (!ret)
    {
        return download_cert_http(issuer, x);
    }
    return ret;
}


namespace snet
{

int verify_cb(int ret, X509_STORE_CTX* ctx)
{
    BIO* std = BIO_new_fp(stdout, BIO_NOCLOSE);
    auto cert = X509_STORE_CTX_get_current_cert(ctx);

    if (cert)
    {
        BIO_printf(std, "-----------------------------\n");
        X509_NAME_print_ex(std, crypto::cert::subjectName(cert), 1,
                           ASN1_STRFLGS_UTF8_CONVERT | XN_FLAG_SEP_COMMA_PLUS);
        BIO_printf(std, "\n");
        X509_NAME_print_ex(std, crypto::cert::issuerName(cert), 1,
                           ASN1_STRFLGS_UTF8_CONVERT | XN_FLAG_SEP_COMMA_PLUS);
        BIO_printf(std, "\n-----------------------------\n");
    }
    auto crl = X509_STORE_CTX_get0_current_crl(ctx);
    if (crl)
    {
        BIO_printf(std, "-----------------------------\n");
        X509_NAME_print_ex(std, X509_CRL_get_issuer(crl), 0,
                           ASN1_STRFLGS_UTF8_CONVERT | XN_FLAG_SEP_COMMA_PLUS);
        BIO_printf(std, "\n-----------------------------\n");
    }
    BIO_free(std);
    return ret;
}

struct Options
{
    std::string cert;
};

class Command final : public cmd::Command
{
public:
    Command()
    {
        parser_.add("help", "Print help message");
        parser_.add("cert", opt::Value(&options_.cert), "Certificate file");
    }

    ~Command() = default;

    void execute(const std::vector<std::string_view>& args) override
    {
        parser_.parse(args);
        if (parser_.isUsed("help"))
        {
            parser_.help(std::cout);
            return;
        }

        crypto::CertManager manager;
        manager.loadStore("/usr/lib/ssl/certs/ca-certificates.crt");
        manager.lookupCRL(::crls_http_cb);
        manager.lookupIssuer(::get_issuer);
        manager.setVerifyCallback(verify_cb);

        crypto::CertVerifier verifier(manager);
        //verifier.setFlag(VerifyFlag::CrlCheck);
        //verifier.setFlag(VerifyFlag::CrlCheckAll);
        verifier.setFlag(VerifyFlag::StrictCheck);
        verifier.setFlag(VerifyFlag::CheckSelfSigned);

        auto cert = crypto::cert::fromStorage(options_.cert);
        auto ec = verifier.verify(cert);

        std::cout << ec.message() << std::endl;
    }

private:
    opt::OptionParser parser_;
    Options options_;
};

REGISTER_COMMAND("verify", "Verify certificate", Command);

} // namespace snet