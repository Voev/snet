#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <unistd.h>

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/store.h>
#include <openssl/x509.h>
#include <openssl/ocsp.h>

#include <openssl/ssl.h>

#include <snet/crypto/cert.hpp>
#include <snet/crypto/cert_name.hpp>
#include <snet/crypto/crl.hpp>
#include <snet/crypto/pointers.hpp>

#include <snet/pki_fetch/cert_crl_loader.hpp>
#include <snet/pki_fetch/url.hpp>

#include <casket/log/log.hpp>
#include <casket/utils/string.hpp>
#include <casket/utils/exception.hpp>

#include <snet/tls/types.hpp>

using namespace casket;
using namespace snet::crypto;

namespace snet::pki_fetch
{

CrlOwningStackPtr FilterValidCrl(CrlStack* crls, time_t now)
{
    if (crls == nullptr)
    {
        return nullptr;
    }

    auto count = sk_X509_CRL_num(crls);
    crypto::ThrowIfTrue(count == 0, "no CRL");

    CrlOwningStackPtr valid{sk_X509_CRL_new_null()};
    crypto::ThrowIfFalse(valid, "bad allocation");

    crypto::ThrowIfFalse(0 < sk_X509_CRL_reserve(valid, count));

    for (int i = 0; i < count; ++i)
    {
        X509Crl* crl = sk_X509_CRL_value(crls, i);
        if (!crl)
        {
            continue;
        }

        const ASN1_TIME* thisUpdate = X509_CRL_get0_lastUpdate(crl);
        const ASN1_TIME* nextUpdate = X509_CRL_get0_nextUpdate(crl);

        if (0 < X509_cmp_time(thisUpdate, &now))
        {
            continue;
        }

        if (nextUpdate != nullptr && 0 >= X509_cmp_time(nextUpdate, &now))
        {
            continue;
        }

        auto copy = Crl::shallowCopy(crl);
        crypto::ThrowIfFalse(0 < sk_X509_CRL_push(valid, copy));
    }

    return valid;
}

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)

static inline int CheckTimeout(const int fd, const int timeout, const int checkOnRead)
{
    fd_set fdset;
    struct timeval timevalue;

    if (fd < 0 || timeout < 0)
    {
        return -1;
    }

    FD_ZERO(&fdset);
    FD_SET(fd, &fdset);
    timevalue.tv_usec = 0;
    timevalue.tv_sec = timeout;

    if (checkOnRead)
    {
        return select(fd + 1, &fdset, nullptr, nullptr, &timevalue);
    }
    return select(fd + 1, nullptr, &fdset, nullptr, &timevalue);
}

int CheckConnection(BIO* conn, const int timeout)
{
    int ret = 0;
    int fd = -1;

    if (conn == nullptr)
    {
        return 0;
    }

    if (0 > BIO_get_fd(conn, &fd))
    {
        return 0;
    }

    if (BIO_should_read(conn))
    {
        ret = CheckTimeout(fd, timeout, 1);
    }
    else if (BIO_should_write(conn))
    {
        ret = CheckTimeout(fd, timeout, 0);
    }
    else
    {
        return 0;
    }

    if (0 == ret)
    {
        return 0;
    }

    if (-1 == ret)
    {
        return 0;
    }
    return 1;
}

template <typename PtrType, typename LoadFunc>
PtrType LoadCertOrCrlByHttp(nonstd::string_view url, int timeout, LoadFunc loadFunc)
{
    OcspReqCtxPtr rctx;
    PtrType result;
    BioPtr bio;
    int fd = -1;
    int ret = 0;

    auto urlData = UrlParser::parse(url);
    casket::ThrowIfFalse(urlData.has_value(), "failed to parse URL '{}'", url);

    bio.reset(BIO_new_connect(urlData->host.data()));
    crypto::ThrowIfFalse(bio != nullptr, "failed to create socket");
    crypto::ThrowIfFalse(0 < BIO_set_conn_port(bio, urlData->port.data()));

    if (urlData->isHttps)
    {
        tls::SslCtxPtr sslCtx{SSL_CTX_new(TLS_client_method())};
        crypto::ThrowIfFalse(sslCtx != nullptr, "failed to create TLS context");

        SSL_CTX_set_mode(sslCtx, SSL_MODE_AUTO_RETRY);

        BioPtr ssl{BIO_new_ssl(sslCtx, 1)};
        crypto::ThrowIfFalse(ssl != nullptr, "failed to create TLS BIO");

        BIO_push(ssl, bio.release());
        bio = std::move(ssl);
    }

    if (timeout != -1)
    {
        BIO_set_nbio(bio, 1);
    }

    ret = BIO_do_connect(bio);
    if (0 >= ret && (-1 == timeout || !BIO_should_retry(bio)))
    {
        return nullptr;
    }

    crypto::ThrowIfFalse(0 < BIO_get_fd(bio, &fd));

    if (-1 != timeout && 0 >= ret)
    {
        if (0 == CheckTimeout(fd, timeout, 0))
        {
            return nullptr;
        }
    }

    rctx.reset(OCSP_REQ_CTX_new(bio, 1024));
    crypto::ThrowIfFalse(rctx != nullptr, "bad allocation");
    crypto::ThrowIfFalse(0 < OCSP_REQ_CTX_http(rctx, "GET", urlData->path.data()));
    crypto::ThrowIfFalse(0 < OCSP_REQ_CTX_add1_header(rctx, "Host", urlData->host.data()));

    while (1)
    {
        typename PtrType::element_type* res = nullptr;
        ret = loadFunc(rctx, &res);

        if (ret == 1 && res != nullptr)
        {
            result.reset(res);
            break;
        }
        else if (ret == 0)
        {
            return nullptr;
        }

        if (-1 == timeout)
        {
            continue;
        }

        if (!CheckConnection(bio, timeout))
        {
            return nullptr;
        }
    }

    return result;
}
#endif // (OPENSSL_VERSION_NUMBER < 0x30000000L)

X509CertPtr LoadCertByHttp(nonstd::string_view url, int timeout)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    return X509CertPtr{X509_load_http(url.data(), nullptr, nullptr, timeout)};
#else
    return LoadCertOrCrlByHttp<X509CertPtr>(url,
                                            timeout,
                                            [](OcspReqCtxPtr& rctx, X509** res) -> int
                                            {
                                                return X509_http_nbio(rctx, res);
                                            });
#endif
}

X509CrlPtr LoadCrlByHttp(nonstd::string_view url, int timeout)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    return X509CrlPtr{X509_CRL_load_http(url.data(), nullptr, nullptr, timeout)};
#else
    return LoadCertOrCrlByHttp<X509CrlPtr>(url,
                                           timeout,
                                           [](OcspReqCtxPtr& rctx, X509_CRL** res) -> int
                                           {
                                               return X509_CRL_http_nbio(rctx, res);
                                           });
#endif
}

static nonstd::string_view GetDistPointUrl(DIST_POINT* dp)
{
    GENERAL_NAMES* gens;

    if (!dp->distpoint || dp->distpoint->type != 0)
    {
        return {};
    }

    gens = dp->distpoint->name.fullname;
    for (int i = 0; i < sk_GENERAL_NAME_num(gens); ++i)
    {
        GENERAL_NAME* gen;
        ASN1_STRING* uri;
        int gtype;

        gen = sk_GENERAL_NAME_value(gens, i);
        uri = (ASN1_STRING*)GENERAL_NAME_get0_value(gen, &gtype);

        if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6)
        {
            nonstd::string_view uptr = (const char*)ASN1_STRING_get0_data(uri);
            if (uptr.compare(0, 7, "http://") == 0 || uptr.compare(0, 8, "https://") == 0)
            {
                return uptr;
            }
        }
    }

    return {};
}

static inline X509CrlPtr LoadCrlByExtention(X509Cert* cert, int nid, int timeout)
{
    CrlDistPointsPtr crldp{Cert::getExtension<CrlDistPoints>(cert, nid)};
    auto count = sk_DIST_POINT_num(crldp);

    for (auto i = 0; i < count; ++i)
    {
        auto dp = sk_DIST_POINT_value(crldp, i);
        auto url = GetDistPointUrl(dp);
        return LoadCrlByHttp(url, timeout);
    }

    return nullptr;
}

CrlOwningStackPtr LocalSearchForCrls(OSSL_CONST_COMPAT X509StoreCtx* ctx, OSSL_CONST_COMPAT X509Name* name)
{
    CrlOwningStackPtr crls{X509_STORE_CTX_get1_crls(ctx, name)};

    crls.reset(FilterValidCrl(crls, time(nullptr)));

    if (sk_X509_CRL_num(crls) > 0)
    {
        return crls;
    }

    return nullptr;
}

static inline void AddCrlToStack(CrlStack* crls, X509Crl* crl)
{
    auto copy = Crl::shallowCopy(crl);
    crypto::ThrowIfFalse(0 < sk_X509_CRL_push(crls, copy));
    copy.release();
}

CrlOwningStackPtr DownloadCrls(OSSL_CONST_COMPAT X509StoreCtx* ctx, int timeout)
{
    CrlOwningStackPtr crls(sk_X509_CRL_new_null());
    crypto::ThrowIfFalse(crls);

    auto store = X509_STORE_CTX_get0_store(ctx);
    auto cert = X509_STORE_CTX_get_current_cert(ctx);

    auto crl = LoadCrlByExtention(cert, NID_crl_distribution_points, timeout);
    if (!crl)
    {
        return nullptr;
    }

    AddCrlToStack(crls, crl);
    crypto::ThrowIfFalse(0 < X509_STORE_add_crl(store, crl));

    crl = LoadCrlByExtention(cert, NID_freshest_crl, timeout);
    if (crl)
    {
        AddCrlToStack(crls, crl);
        crypto::ThrowIfFalse(0 < X509_STORE_add_crl(store, crl));
    }

    return crls;
}

} // namespace snet::pki_fetch