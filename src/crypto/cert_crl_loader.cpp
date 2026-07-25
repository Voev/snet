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
#include <snet/crypto/cert_crl_loader.hpp>
#include <snet/crypto/pointers.hpp>

#include <casket/log/log.hpp>

namespace snet::crypto
{

STACK_OF(X509_CRL) * filter_valid_crl(STACK_OF(X509_CRL) * crls, time_t now)
{
    if (crls == NULL)
    {
        return NULL;
    }

    int count = sk_X509_CRL_num(crls);
    if (count == 0)
    {
        return NULL;
    }

    STACK_OF(X509_CRL)* valid = sk_X509_CRL_new_null();
    if (valid == NULL)
    {
        return NULL;
    }

    if (!sk_X509_CRL_reserve(valid, count))
    {
        sk_X509_CRL_free(valid);
        return NULL;
    }

    for (int i = 0; i < count; ++i)
    {
        X509_CRL* crl = sk_X509_CRL_value(crls, i);
        if (crl == NULL)
        {
            continue;
        }

        const ASN1_TIME* thisUpdate = X509_CRL_get0_lastUpdate(crl);
        const ASN1_TIME* nextUpdate = X509_CRL_get0_nextUpdate(crl);

        if (thisUpdate == NULL)
        {
            continue;
        }

        if (0 < X509_cmp_time(thisUpdate, &now))
        {
            continue;
        }

        if (nextUpdate != NULL && 0 >= X509_cmp_time(nextUpdate, &now))
        {
            continue;
        }

        if (!X509_CRL_up_ref(crl))
        {
            continue;
        }

        if (!sk_X509_CRL_push(valid, crl))
        {
            X509_CRL_free(crl);
        }
    }

    return valid;
}

static inline int sk_X509_CRL_push_with_up_ref(STACK_OF(X509_CRL) * crls, X509_CRL* crl)
{
    if (crl == NULL || !X509_CRL_up_ref(crl))
    {
        return 0;
    }

    if (!sk_X509_CRL_push(crls, crl))
    {
        X509_CRL_free(crl);
        return 0;
    }
    return 1;
}

static inline int check_timeout(const int fd, const int timeout, const int checkOnRead)
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
        return select(fd + 1, &fdset, NULL, NULL, &timevalue);
    }
    return select(fd + 1, NULL, &fdset, NULL, &timevalue);
}

int bio_check_connection(BIO* conn, const int timeout)
{
    int ret = 0;
    int fd = -1;

    if (conn == NULL)
    {
        return 0;
    }

    if (0 > BIO_get_fd(conn, &fd))
    {
        return 0;
    }

    if (BIO_should_read(conn))
    {
        ret = check_timeout(fd, timeout, 1);
    }
    else if (BIO_should_write(conn))
    {
        ret = check_timeout(fd, timeout, 0);
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

X509CrlPtr LoadCrlByHttp(const char* url, int timeout)
{
    X509CrlPtr crl;
    OCSP_REQ_CTX* rctx = NULL;
    BIO* bio = NULL;
    SSL_CTX* sslCtx = NULL;
    char* host = NULL;
    char* port = NULL;
    char* path = NULL;
    int useSsl = 0;
    int fd = -1;
    int ret = 0;

    if (!OCSP_parse_url(url, &host, &port, &path, &useSsl) || !host || !port || !path)
    {
        goto end;
    }

    bio = BIO_new_connect(host);
    if (!bio || !BIO_set_conn_port(bio, port))
    {
        goto end;
    }

    if (useSsl)
    {
        BIO* ssl = NULL;
        BIO* tmp = NULL;

        sslCtx = SSL_CTX_new(TLS_client_method());
        if (sslCtx == NULL)
        {
            goto end;
        }

        SSL_CTX_set_mode(sslCtx, SSL_MODE_AUTO_RETRY);

        ssl = BIO_new_ssl(sslCtx, 1);
        if (ssl == NULL)
        {
            goto end;
        }

        tmp = BIO_push(ssl, bio);
        if (tmp == NULL)
        {
            BIO_free(ssl);
            BIO_free(bio);
            bio = NULL;
            goto end;
        }
        bio = tmp;
    }

    if (timeout != -1)
    {
        BIO_set_nbio(bio, 1);
    }

    ret = BIO_do_connect(bio);
    if (0 >= ret && (-1 == timeout || !BIO_should_retry(bio)))
    {
        goto end;
    }

    if (0 > BIO_get_fd(bio, &fd))
    {
        goto end;
    }

    if (-1 != timeout && 0 >= ret)
    {
        if (0 == check_timeout(fd, timeout, 0))
        {
            goto end;
        }
    }

    rctx = OCSP_REQ_CTX_new(bio, 1024);
    if (rctx == NULL || !OCSP_REQ_CTX_http(rctx, "GET", path) || !OCSP_REQ_CTX_add1_header(rctx, "Host", host))
    {
        goto end;
    }

    while (1)
    {
        X509_CRL* res = NULL;
        ret = X509_CRL_http_nbio(rctx, &res);

        if (ret == 1 && res != nullptr)
        {
            crl.reset(res);
            break;
        }
        else if (ret == 0)
        {
            goto end;
        }

        if (-1 == timeout)
        {
            continue;
        }

        if (!bio_check_connection(bio, timeout))
        {
            goto end;
        }
    }

    if (crl != NULL)
    {
        ret = 1;
    }

end:
    OPENSSL_free(host);
    OPENSSL_free(path);
    OPENSSL_free(port);
    SSL_CTX_free(sslCtx);
    OCSP_REQ_CTX_free(rctx);
    BIO_free_all(bio);
    return crl;
}

X509CertPtr LoadCertByHttp(const char* url, int timeout)
{
    OCSP_REQ_CTX* rctx = NULL;
    X509* cert = NULL;
    BIO* bio = NULL;
    SSL_CTX* sslCtx = NULL;
    char* host = NULL;
    char* port = NULL;
    char* path = NULL;
    int useSsl = 0;
    int fd = -1;
    int ret = 0;

    if (!OCSP_parse_url(url, &host, &port, &path, &useSsl) || !host || !port || !path)
    {
        goto end;
    }

    bio = BIO_new_connect(host);
    if (!bio || !BIO_set_conn_port(bio, port))
    {
        goto end;
    }

    if (useSsl)
    {
        BIO* ssl = NULL;
        BIO* tmp = NULL;

        sslCtx = SSL_CTX_new(TLS_client_method());
        if (sslCtx == NULL)
        {
            goto end;
        }

        SSL_CTX_set_mode(sslCtx, SSL_MODE_AUTO_RETRY);

        ssl = BIO_new_ssl(sslCtx, 1);
        if (ssl == NULL)
        {
            goto end;
        }

        tmp = BIO_push(ssl, bio);
        if (tmp == NULL)
        {
            BIO_free(ssl);
            BIO_free(bio);
            bio = NULL;
            goto end;
        }
        bio = tmp;
    }

    if (timeout != -1)
    {
        BIO_set_nbio(bio, 1);
    }

    ret = BIO_do_connect(bio);
    if (0 >= ret && (-1 == timeout || !BIO_should_retry(bio)))
    {
        goto end;
    }

    if (0 > BIO_get_fd(bio, &fd))
    {
        goto end;
    }

    if (-1 != timeout && 0 >= ret)
    {
        if (0 == check_timeout(fd, timeout, 0))
        {
            goto end;
        }
    }

    rctx = OCSP_REQ_CTX_new(bio, 1024);
    if (rctx == NULL || !OCSP_REQ_CTX_http(rctx, "GET", path) || !OCSP_REQ_CTX_add1_header(rctx, "Host", host))
    {
        goto end;
    }

    while (1)
    {
        ret = X509_http_nbio(rctx, &cert);
        if (ret == 1)
        {
            break;
        }
        else if (ret == 0)
        {
            goto end;
        }

        if (-1 == timeout)
        {
            continue;
        }

        if (!bio_check_connection(bio, timeout))
        {
            goto end;
        }
    }

    if (cert != NULL)
    {
        ret = 1;
    }

end:
    if (!ret)
    {
        X509_free(cert);
        cert = NULL;
    }
    OPENSSL_free(host);
    OPENSSL_free(path);
    OPENSSL_free(port);
    SSL_CTX_free(sslCtx);
    OCSP_REQ_CTX_free(rctx);
    BIO_free_all(bio);
    return X509CertPtr{cert};
}

static const char* GetDistPointUrl(DIST_POINT* dp)
{
    GENERAL_NAMES* gens;

    if (!dp->distpoint || dp->distpoint->type != 0)
    {
        return NULL;
    }

    gens = dp->distpoint->name.fullname;
    for (int i = 0; i < sk_GENERAL_NAME_num(gens); i++)
    {
        GENERAL_NAME* gen;
        ASN1_STRING* uri;
        int gtype;

        gen = sk_GENERAL_NAME_value(gens, i);
        uri = (ASN1_STRING*)GENERAL_NAME_get0_value(gen, &gtype);

        if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6)
        {
            const char* uptr = (const char*)ASN1_STRING_get0_data(uri);
            if (0 == strncmp(uptr, "http://", 7) || 0 == strncmp(uptr, "https://", 8))
            {
                return uptr;
            }
        }
    }

    return NULL;
}

static inline X509CrlPtr LoadCrlByExtention(X509Cert* cert, int nid)
{
    CrlDistPointsPtr crldp{Cert::getExtension<CrlDistPoints>(cert, nid)};
    auto count = sk_DIST_POINT_num(crldp);

    for (auto i = 0; i < count; ++i)
    {
        auto dp = sk_DIST_POINT_value(crldp, i);
        auto url = GetDistPointUrl(dp);

        if (url)
        {
            return LoadCrlByHttp(url, 5);
        }
    }

    return nullptr;
}

CrlOwningStackPtr LocalSearchForCrls(OSSL_CONST_COMPAT X509StoreCtx* ctx, OSSL_CONST_COMPAT X509Name* name)
{
    CrlOwningStackPtr crls{X509_STORE_CTX_get1_crls(ctx, name)};

    crls.reset(filter_valid_crl(crls, time(nullptr)));

    if (sk_X509_CRL_num(crls) > 0)
    {
        return crls;
    }

    return nullptr;
}

CrlOwningStackPtr DownloadCrls(OSSL_CONST_COMPAT X509StoreCtx* ctx)
{
    CrlOwningStackPtr crls(sk_X509_CRL_new_null());
    crypto::ThrowIfFalse(crls);

    auto store = X509_STORE_CTX_get0_store(ctx);
    auto cert = X509_STORE_CTX_get_current_cert(ctx);

    auto crl = LoadCrlByExtention(cert, NID_crl_distribution_points);
    if (!crl)
    {
        return nullptr;
    }

    crypto::ThrowIfFalse(0 < X509_STORE_add_crl(store, crl));
    crypto::ThrowIfFalse(0 < sk_X509_CRL_push_with_up_ref(crls, crl));

    crl = LoadCrlByExtention(cert, NID_freshest_crl);
    if (crl)
    {
        crypto::ThrowIfFalse(0 < X509_STORE_add_crl(store, crl));
        crypto::ThrowIfFalse(0 < sk_X509_CRL_push_with_up_ref(crls, crl));
    }

    return crls;
}

} // namespace snet::crypto