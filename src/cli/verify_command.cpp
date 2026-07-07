
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/safestack.h>

#include <casket/opt/opt.hpp>
#include <casket/log/log.hpp>
#include <casket/nonstd/string_view.hpp>
#include <snet/utils/finally.hpp>

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

X509CrlPtr DownloadCrl(nonstd::string_view uri)
{
    CSK_LOG_DEBUG("loading CRL from URI: %s", uri.data());

    X509CrlPtr crl(X509_CRL_load_http(uri.data(), nullptr, nullptr, 0));

    if (crl)
    {
        CSK_LOG_DEBUG("successfully loaded CRL from %s", uri.data());
    }
    else
    {
        CSK_LOG_WARNING("failed to load CRL from %s", uri.data());
    }

    return crl;
}

X509CertPtr DownloadCert(nonstd::string_view uri)
{
    CSK_LOG_DEBUG("loading certificate from URI: %s", uri.data());

    X509CertPtr cert(X509_load_http(uri.data(), nullptr, nullptr, 0));

    if (cert)
    {
        CSK_LOG_DEBUG("successfully loaded certificate from %s", uri.data());
    }
    else
    {
        CSK_LOG_WARNING("failed to load certificate from %s", uri.data());
    }

    return cert;
}

template <typename T>
T* GetExtension(X509Cert* cert, int extensionNid)
{
    const char* extName = OBJ_nid2sn(extensionNid);
    CSK_LOG_DEBUG("trying to get extension %s (NID=%d)", extName, extensionNid);

    T* ext = static_cast<T*>(X509_get_ext_d2i(cert, extensionNid, nullptr, nullptr));

    if (ext)
    {
        CSK_LOG_DEBUG("found extension %s", extName);
    }
    else
    {
        CSK_LOG_DEBUG("extension %s not found", extName);
    }

    return ext;
}

static CrlStack* LookupCrls(const X509_STORE_CTX* ctx, const X509Name* name)
{
    std::string nameStr = CertName::toString(name);
    CSK_LOG_DEBUG("trying to lookup CRL for name: %s", nameStr.c_str());

    CrlOwningStackPtr crls;
    try
    {
        crls.reset(X509_STORE_CTX_get1_crls(ctx, name));
        if (crls)
        {
            int count = sk_X509_CRL_num(crls.get());
            CSK_LOG_DEBUG("found %d CRL(s) in context cache for %s", count, nameStr.c_str());
            return crls.release();
        }

        CSK_LOG_DEBUG("no CRL in cache for %s, trying to download via CDP", nameStr.c_str());

        X509Cert* cert = X509_STORE_CTX_get_current_cert(ctx);
        if (!cert)
        {
            CSK_LOG_WARNING("no current certificate in context");
            return nullptr;
        }

        std::string certName = CertName::toString(Cert::subjectName(cert));
        CSK_LOG_DEBUG("current certificate subject: %s", certName.c_str());

        CrlDistPointsPtr crldp(GetExtension<CrlDistPoints>(cert, NID_crl_distribution_points));
        if (!crldp)
        {
            CSK_LOG_DEBUG("no CDP extension in certificate %s", certName.c_str());
            return nullptr;
        }

        int dpCount = sk_DIST_POINT_num(crldp);
        CSK_LOG_DEBUG("found %d distribution point(s) in CDP", dpCount);

        crls.reset(sk_X509_CRL_new_null());
        ThrowIfFalse(crls);

        int downloadedCount = 0;

        for (int i = 0; i < dpCount; ++i)
        {
            DIST_POINT* dp = sk_DIST_POINT_value(crldp, i);
            if (!dp->distpoint || dp->distpoint->type != 0)
            {
                CSK_LOG_DEBUG("distribution point %d has no fullname, skipping", i);
                continue;
            }

            GENERAL_NAMES* gens = dp->distpoint->name.fullname;
            int genCount = sk_GENERAL_NAME_num(gens);
            CSK_LOG_DEBUG("distribution point %d has %d general name(s)", i, genCount);

            int gtype = 0;
            for (int j = 0; j < genCount; ++j)
            {
                GENERAL_NAME* gen = sk_GENERAL_NAME_value(gens, j);
                ASN1_STRING* uri = static_cast<ASN1_STRING*>(GENERAL_NAME_get0_value(gen, &gtype));

                if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6)
                {
                    std::string uriStr(reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri)),
                                       ASN1_STRING_length(uri));
                    CSK_LOG_DEBUG("found URI at gen[%d]: %s", j, uriStr.c_str());

                    auto crl = DownloadCrl(uriStr);
                    if (crl)
                    {
                        X509_CRL* rawCrl = crl.get();
                        int pushResult = sk_X509_CRL_push(crls.get(), rawCrl);

                        if (pushResult > 0)
                        {
                            crl.release();
                            downloadedCount++;
                            CSK_LOG_DEBUG("successfully added CRL from %s (stack now has %d elements)",
                                          uriStr.c_str(),
                                          sk_X509_CRL_num(crls.get()));
                        }
                        else
                        {
                            CSK_LOG_WARNING("failed to add CRL to stack from %s", uriStr.c_str());
                        }
                    }
                    else
                    {
                        CSK_LOG_WARNING("failed to download CRL from %s", uriStr.c_str());
                    }
                }
                else if (gtype == GEN_URI)
                {
                    CSK_LOG_WARNING("URI too short (length=%d), skipping", ASN1_STRING_length(uri));
                }
                else
                {
                    CSK_LOG_DEBUG("general name type %d is not URI, skipping", gtype);
                }
            }
        }

        CSK_LOG_DEBUG("downloaded %d CRL(s) for %s", downloadedCount, nameStr.c_str());
    }
    catch (const std::exception& e)
    {
        CSK_LOG_ERROR("exception: %s", e.what());
        std::cout << "failed to lookup CRLs: " << e.what() << std::endl;
    }

    int total = crls ? sk_X509_CRL_num(crls.get()) : 0;
    CSK_LOG_DEBUG("returning %d CRL(s) for %s", total, nameStr.c_str());
    return crls.release();
}

std::vector<std::string> GetURIFromAuthInfoAccess(const AuthInfoAccess* aia)
{
    std::vector<std::string> uris;

    if (!aia)
    {
        CSK_LOG_ERROR("AIA pointer is null");
        return uris;
    }

    int count = sk_ACCESS_DESCRIPTION_num(aia);
    CSK_LOG_DEBUG("scanning %d access description(s)", count);

    for (int i = 0; i < count; i++)
    {
        ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(aia, i);
        int methodNid = OBJ_obj2nid(ad->method);

        CSK_LOG_DEBUG("access[%d] method NID=%d", i, methodNid);

        if (methodNid == NID_ad_ca_issuers)
        {
            CSK_LOG_DEBUG("access[%d] is caIssuers", i);

            if (ad->location->type == GEN_URI)
            {
                ASN1_IA5STRING* uri = ad->location->d.uniformResourceIdentifier;
                if (uri->type != V_ASN1_IA5STRING || !uri->data || uri->length == 0)
                {
                    CSK_LOG_WARNING(
                        "access[%d] URI is invalid (type=%d, data=%p, len=%d)", i, uri->type, uri->data, uri->length);
                    continue;
                }

                std::string uriStr(reinterpret_cast<char*>(uri->data), uri->length);
                uris.emplace_back(uriStr);
                CSK_LOG_DEBUG("added URI[%zu]: %s", uris.size() - 1, uriStr.c_str());
            }
            else
            {
                CSK_LOG_DEBUG("access[%d] location type %d is not URI", i, ad->location->type);
            }
        }
        else
        {
            CSK_LOG_DEBUG("access[%d] method NID=%d is not caIssuers (NID=%d)", i, methodNid, NID_ad_ca_issuers);
        }
    }

    CSK_LOG_DEBUG("found %zu URI(s)", uris.size());
    return uris;
}

static int GetIssuer(X509** issuer, X509_STORE_CTX* ctx, X509* subject)
{
    std::string subjectName = CertName::toString(Cert::subjectName(subject));
    CSK_LOG_DEBUG("getIssuer called for subject: %s", subjectName.c_str());

    if (X509_STORE_CTX_get1_issuer(issuer, ctx, subject))
    {
        std::string issuerName = CertName::toString(Cert::subjectName(*issuer));
        int isSelfSigned = (X509_check_issued(*issuer, *issuer) == X509_V_OK);

        CSK_LOG_DEBUG("found issuer locally:");
        CSK_LOG_DEBUG("  issuer: %s", issuerName.c_str());
        CSK_LOG_DEBUG("  self-signed: %s", isSelfSigned ? "YES (root)" : "NO (intermediate)");

        return 1;
    }

    CSK_LOG_DEBUG("issuer NOT found locally");
    CSK_LOG_DEBUG("attempting to download issuer via AIA...");

    AuthInfoAccessPtr aia(GetExtension<AuthInfoAccess>(subject, NID_info_access));
    if (!aia)
    {
        CSK_LOG_DEBUG("no AIA extension found in certificate");
        return 0;
    }

    auto uris = GetURIFromAuthInfoAccess(aia);
    if (uris.empty())
    {
        CSK_LOG_DEBUG("no URIs found in AIA extension");
        return 0;
    }

    CSK_LOG_DEBUG("found %zu URI(s) in AIA", uris.size());

    for (size_t i = 0; i < uris.size(); ++i)
    {
        const auto& uri = uris[i];
        CSK_LOG_DEBUG("  URI[%zu]: %s", i, uri.c_str());

        auto cert = DownloadCert(uri);
        if (!cert)
        {
            CSK_LOG_DEBUG("  failed to download certificate from URI[%zu]", i);
            continue;
        }

        CSK_LOG_DEBUG("  successfully downloaded certificate from URI[%zu]", i);

        int checkResult = X509_check_issued(cert.get(), subject);
        if (checkResult != X509_V_OK)
        {
            CSK_LOG_DEBUG("  downloaded certificate is NOT a valid issuer for %s (check_result=%d)",
                          subjectName.c_str(),
                          checkResult);
            continue;
        }

        CSK_LOG_DEBUG("  downloaded certificate IS a valid issuer");

        if (X509_check_issued(cert.get(), cert.get()) == X509_V_OK)
        {
            CSK_LOG_DEBUG("  downloaded certificate is SELF-SIGNED (potential root)");

            X509* root = nullptr;
            if (X509_STORE_CTX_get1_issuer(&root, ctx, cert.get()))
            {
                std::string root_name = CertName::toString(Cert::subjectName(root));
                CSK_LOG_DEBUG("  root certificate FOUND in trusted store: %s", root_name.c_str());
                *issuer = root;
                return 1;
            }
            else
            {
                CSK_LOG_DEBUG("  root certificate NOT found in trusted store - REJECTING");
                continue;
            }
        }
        else
        {
            CSK_LOG_DEBUG("  downloaded certificate is INTERMEDIATE (not self-signed) - ACCEPTING");
            *issuer = cert.release();
            return 1;
        }
    }

    CSK_LOG_DEBUG("no valid issuer found for %s", subjectName.c_str());
    return 0;
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
        X509_NAME_print_ex(out, Cert::subjectName(cert), 1, ASN1_STRFLGS_UTF8_CONVERT | XN_FLAG_SEP_SPLUS_SPC);
        BIO_printf(out, "\nIssuer: ");
        X509_NAME_print_ex(out, Cert::issuerName(cert), 1, ASN1_STRFLGS_UTF8_CONVERT | XN_FLAG_SEP_SPLUS_SPC);

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
    std::string logLevel;
    std::string certPath;
    std::string caStorePath;
    bool noCheckCrl{false};
    bool checkAllCrl{false};
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
            OptionBuilder("log", Value(&options_.logLevel))
                .setDescription("Log level")
                .setDefaultValue("warn")
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
                .setDescription("Disable CRL checking for the end certificate")
                .build()
        );
        parser_.add(
            OptionBuilder("check_all_crl")
                .setDescription("Enable checking of all CRLs in the certificate chain")
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

        LogWorker logWorker(std::make_unique<ConsoleSink>());
        Finally _{[&logWorker]()
                  {
                      logWorker.stop();
                  }};

        AsyncLogger::getInstance().setLevel(StringToLevel(options_.logLevel));

        CertManager manager;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
        manager.loadStore(options_.caStorePath);
        manager.setLookupCRLs(LookupCrls);
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

        if (options_.checkAllCrl)
        {
            verifier.setFlag(VerifyFlag::CrlCheckAll);
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