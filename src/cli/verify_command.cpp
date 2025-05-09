#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/safestack.h>

#include <casket/opt/option_builder.hpp>
#include <casket/opt/cmd_line_options_parser.hpp>

#include <snet/cli/command_dispatcher.hpp>

#include <snet/crypto/cert.hpp>
#include <snet/crypto/cert_verifier.hpp>

using namespace casket;
using namespace casket::opt;
using namespace snet::crypto;

namespace snet
{

CrlPtr DownloadCRL(std::string_view uri)
{
    return CrlPtr(X509_CRL_load_http(uri.data(), nullptr, nullptr, 0));
}

void LoadCrlsByDistPoint(CrlStack* crls, STACK_OF(DIST_POINT) * crldp)
{
    for (int i = 0; i < sk_DIST_POINT_num(crldp); ++i)
    {
        DIST_POINT* dp = sk_DIST_POINT_value(crldp, i);
        if (!dp->distpoint || dp->distpoint->type != 0)
        {
            continue;
        }

        GENERAL_NAMES* gens = dp->distpoint->name.fullname;
        int gtype = 0;

        for (int j = 0; j < sk_GENERAL_NAME_num(gens); ++j)
        {
            GENERAL_NAME* gen = sk_GENERAL_NAME_value(gens, i);
            ASN1_STRING* uri = (ASN1_STRING*)GENERAL_NAME_get0_value(gen, &gtype);
            if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6)
            {
                auto crl = DownloadCRL((const char*)ASN1_STRING_get0_data(uri));
                if (crl)
                {
                    sk_X509_CRL_push(crls, crl.release());
                }
            }
        }
    }
}

static STACK_OF(X509_CRL) * LookupCRLs(const X509_STORE_CTX* ctx, const X509_NAME* nm)
{
    CrlOwningStackPtr crls(X509_STORE_CTX_get1_crls(ctx, nm));
    if (!crls || sk_X509_CRL_num(crls) == 0)
    {
        Cert* cert = X509_STORE_CTX_get_current_cert(ctx);
        STACK_OF(DIST_POINT)* crldp = (STACK_OF(DIST_POINT)*)X509_get_ext_d2i(
            cert, NID_crl_distribution_points, nullptr, nullptr);

        LoadCrlsByDistPoint(crls, crldp);
    }
    return crls.release();
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

int DownloadCert(X509** issuer, X509* x)
{
    auto aia = X509_get1_issuers(x);
    for (int i = 0; i < sk_OPENSSL_STRING_num(aia); ++i)
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

static int GetIssuer(X509** issuer, X509_STORE_CTX* ctx, X509* x)
{
    int ret = X509_STORE_CTX_get1_issuer(issuer, ctx, x);
    if (!ret)
    {
        return DownloadCert(issuer, x);
    }
    return ret;
}

int VerifyCallback(int ret, X509_STORE_CTX* ctx)
{
    BIO* std = BIO_new_fp(stdout, BIO_NOCLOSE);
    auto cert = X509_STORE_CTX_get_current_cert(ctx);

    if (cert)
    {
        BIO_printf(std, "-----------------------------\n");
        X509_NAME_print_ex(std, cert::subjectName(cert), 1,
                           ASN1_STRFLGS_UTF8_CONVERT | XN_FLAG_SEP_COMMA_PLUS);
        BIO_printf(std, "\n");
        X509_NAME_print_ex(std, cert::issuerName(cert), 1,
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
    std::string certPath;
    std::string caStorePath;
};

class Command final : public cmd::Command
{
public:
    Command()
    {
        // clang-format off
        parser_.add(
            OptionBuilder("help")
                .setDescription("Print help message")
                .build()
        );
        parser_.add(
            OptionBuilder("cert", Value(&options_.certPath))
                .setDescription("Path to certificate")
                .build()
        );
        parser_.add(
            OptionBuilder("ca_store", Value(&options_.caStorePath))
                .setDescription("Path to certificate authority store")
                .setDefaultValue("/usr/lib/ssl/certs/ca-certificates.crt")
                .build()
        );
        // clang-format on
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
        parser_.validate();

        CertManager manager;
        manager.loadStore(options_.caStorePath);
        manager.setLookupCRLs(LookupCRLs);
        manager.setGetIssuer(GetIssuer);
        manager.setVerifyCallback(VerifyCallback);

        CertVerifier verifier(manager);
        verifier.setFlag(VerifyFlag::StrictCheck);
        verifier.setFlag(VerifyFlag::CheckSelfSigned);

        auto cert = cert::fromStorage(options_.certPath);
        auto ec = verifier.verify(cert);

        std::cout << ec.message() << std::endl;
    }

private:
    CmdLineOptionsParser parser_;
    Options options_;
};

REGISTER_COMMAND("verify", "Verify certificate", Command);

} // namespace snet