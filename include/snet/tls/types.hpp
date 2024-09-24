#pragma once
#include <cstdint>
#include <memory>
#include <snet/utils/custom_unique_ptr.hpp>

#include <openssl/ssl.h>

namespace snet::tls
{

enum class Side
{
    Client = 0,
    Server
};

enum class ProtocolVersion : std::uint16_t
{
    SSLv2_0 = SSL2_VERSION,
    SSLv3_0 = SSL3_VERSION,
    TLSv1_0 = TLS1_VERSION,
    TLSv1_1 = TLS1_1_VERSION,
    TLSv1_2 = TLS1_2_VERSION,
    TLSv1_3 = TLS1_3_VERSION
};

using ProtocolVersionRange = std::pair<ProtocolVersion, ProtocolVersion>;

enum class VerifyMode
{
    None = 0x00,
    Peer = 0x01,
    FailIfNoPeerCert = 0x02,
    ClientOnce = 0x04,
    PostHandhsake = 0x08
};

using VerifyCallback = int (*)(int, X509_STORE_CTX*);

enum Mode : std::uint32_t
{
    EnablePartialWrite = SSL_MODE_ENABLE_PARTIAL_WRITE,
    AcceptMovingWriteBuffer = SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER,
    AutoRetry = SSL_MODE_AUTO_RETRY,
    NoAutoChain = SSL_MODE_NO_AUTO_CHAIN,
    ReleaseBuffers = SSL_MODE_RELEASE_BUFFERS,
    SendFallbackSCSV = SSL_MODE_SEND_FALLBACK_SCSV,
    SendClientHelloTime = SSL_MODE_SEND_CLIENTHELLO_TIME,
    SendServerHelloTime = SSL_MODE_SEND_SERVERHELLO_TIME,
    Async = SSL_MODE_ASYNC
};

enum SessionCacheMode : std::uint16_t
{
    CacheOff = SSL_SESS_CACHE_OFF,
    CacheClient = SSL_SESS_CACHE_CLIENT,
    CacheServer = SSL_SESS_CACHE_SERVER,
    CacheBoth = SSL_SESS_CACHE_BOTH,
    CacheNoAutoClear = SSL_SESS_CACHE_NO_AUTO_CLEAR,
    CacheNoInternal = SSL_SESS_CACHE_NO_INTERNAL,
    CacheNoInternalLookup = SSL_SESS_CACHE_NO_INTERNAL_LOOKUP,
    CacheNoInternalStore = SSL_SESS_CACHE_NO_INTERNAL_STORE,
};

DEFINE_CUSTOM_UNIQUE_PTR(SslPtr, SSL, SSL_free);
DEFINE_CUSTOM_UNIQUE_PTR(SslCtxPtr, SSL_CTX, SSL_CTX_free);
DEFINE_CUSTOM_UNIQUE_PTR(SslSessionPtr, SSL_SESSION, SSL_SESSION_free);

DEFINE_CUSTOM_UNIQUE_PTR(BioPtr, BIO, BIO_free_all);

} // namespace snet::tls