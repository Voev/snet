
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/safestack.h>

#include <casket/log/log_manager.hpp>
#include <casket/opt/option_builder.hpp>
#include <casket/opt/cmd_line_options_parser.hpp>

#include <snet/cli/command_dispatcher.hpp>

#include <snet/crypto/cert.hpp>
#include <snet/crypto/cert_verifier.hpp>
#include <snet/crypto/exception.hpp>

using namespace casket;
using namespace casket::opt;
using namespace snet::crypto;

namespace snet
{

static bool bPrint{false};

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)

X509CrlPtr DownloadCRL(std::string_view uri)
{
    return X509CrlPtr(X509_CRL_load_http(uri.data(), nullptr, nullptr, 0));
}

X509CertPtr DownloadCert(std::string_view uri)
{
    return X509CertPtr(X509_load_http(uri.data(), nullptr, nullptr, 0));
}

template <typename T>
T* GetExtension(X509Cert* cert, int extensionNid)
{
    return static_cast<T*>(X509_get_ext_d2i(cert, extensionNid, nullptr, nullptr));
}

static CrlStack* LookupCRLs(const X509_STORE_CTX* ctx, const X509Name* name)
{
    CrlOwningStackPtr crls;
    try
    {
        crls.reset(X509_STORE_CTX_get1_crls(ctx, name));
        if (!crls)
        {
            X509Cert* cert = X509_STORE_CTX_get_current_cert(ctx);
            CrlDistPointsPtr crldp(GetExtension<CrlDistPoints>(cert, NID_crl_distribution_points));
            if (!crldp)
            {
                return nullptr;
            }

            crls.reset(sk_X509_CRL_new_null());
            ThrowIfFalse(crls);

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
                    ASN1_STRING* uri = static_cast<ASN1_STRING*>(GENERAL_NAME_get0_value(gen, &gtype));

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
    }
    catch (const std::exception& e)
    {
        casket::error("{}", e.what());
    }
    return crls.release();
}

std::vector<std::string> GetURIFromAuthInfoAccess(const AuthInfoAccess* aia)
{
    std::vector<std::string> uris;
    for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++)
    {
        ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(aia, i);
        if (OBJ_obj2nid(ad->method) == NID_ad_ca_issuers)
        {
            if (ad->location->type == GEN_URI)
            {
                ASN1_IA5STRING* uri = ad->location->d.uniformResourceIdentifier;
                if (uri->type != V_ASN1_IA5STRING || !uri->data || uri->length == 0)
                    continue;
                uris.emplace_back(reinterpret_cast<char*>(uri->data), uri->length);
            }
        }
    }
    return uris;
}

static int GetIssuer(X509** issuer, X509_STORE_CTX* ctx, X509* subject)
{
    if (!X509_STORE_CTX_get1_issuer(issuer, ctx, subject))
    {
        AuthInfoAccessPtr aia(GetExtension<AuthInfoAccess>(subject, NID_info_access));
        if (!aia)
        {
            return 0;
        }

        auto uris = GetURIFromAuthInfoAccess(aia);
        for (const auto& uri : uris)
        {
            auto cert = DownloadCert(uri);
            if (cert)
            {
                *issuer = cert.release();
                return 1;
            }
        }
    }

    return 1;
}

#endif

int VerifyCallback(int ret, X509_STORE_CTX* ctx)
{
    auto cert = X509_STORE_CTX_get_current_cert(ctx);
    auto depth = X509_STORE_CTX_get_error_depth(ctx); 

    BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);

    std::string spaces(40, '-');
    BIO_printf(out, "%s\nCertificate #%d\n%s\n", spaces.c_str(), depth, spaces.c_str());
    if (cert)
    {
        BIO_printf(out, "Serial Number: ");
        BN_print(out, Cert::serialNumber(cert));
        BIO_printf(out, "\nSubject: ");
        X509_NAME_print_ex(out, Cert::subjectName(cert), 1,
                           ASN1_STRFLGS_UTF8_CONVERT | XN_FLAG_SEP_SPLUS_SPC);
        BIO_printf(out, "\nIssuer: ");
        X509_NAME_print_ex(out, Cert::issuerName(cert), 1,
                           ASN1_STRFLGS_UTF8_CONVERT | XN_FLAG_SEP_SPLUS_SPC);

        std::tm* localTime;
        char buffer[80];

        auto notBefore = Cert::notBefore(cert);
        localTime = std::localtime(&notBefore);
        std::strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", localTime);
        BIO_printf(out, "\nNot Before: %s", buffer);

        auto notAfter = Cert::notAfter(cert);
        localTime = std::localtime(&notAfter);
        std::strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", localTime);
        BIO_printf(out, "\nNot After: %s\n", buffer);

        EVP_PKEY_print_public(out, Cert::publicKey(cert), 0, nullptr);

        auto error = verify::MakeErrorCode(static_cast<verify::Error>(X509_STORE_CTX_get_error(ctx)));
        BIO_printf(out, "Status: %s\n", error.message().c_str());

        if (bPrint)
        {
            PEM_write_bio_X509(out, cert);
        }
    }

    BIO_free(out);
    return ret;
}

struct Options
{
    std::string certPath;
    std::string caStorePath;
    bool noCheckCrl{false};
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
                .setRequired()
                .build()
        );
        parser_.add(
            OptionBuilder("no_check_crl")
                .setDescription("Disable check by CRLs")
                .build()
        );
        parser_.add(
            OptionBuilder("print")
                .setDescription("Print certificate chain")
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

        options_.noCheckCrl = parser_.isUsed("no_check_crl");
        bPrint = parser_.isUsed("print");

        CertManager manager;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
        manager.loadStore(options_.caStorePath);
        manager.setLookupCRLs(LookupCRLs);
        manager.setGetIssuer(GetIssuer);
#endif
        manager.setVerifyCallback(VerifyCallback);

        CertVerifier verifier(manager);
        verifier.setFlag(VerifyFlag::StrictCheck);
        verifier.setFlag(VerifyFlag::CheckSelfSigned);

        if (!options_.noCheckCrl)
        {
            verifier.setFlag(VerifyFlag::CrlCheck);
        }

        auto cert = Cert::fromStorage(options_.certPath);
        verifier.verify(cert);
    }

private:
    CmdLineOptionsParser parser_;
    Options options_;
};

REGISTER_COMMAND("verify", "Verify certificate", Command);

} // namespace snet