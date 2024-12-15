#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <snet/utils/custom_unique_ptr.hpp>

#include <openssl/kdf.h>
#include <openssl/ssl.h>
#include <openssl/store.h>

namespace snet::tls
{

enum class Side
{
    Client = 0,
    Server
};

enum class RecordType : uint8_t {
   Invalid = 0,  // RFC 8446 (TLS 1.3)
   ChangeCipherSpec = 20,
   Alert = 21,
   Handshake = 22,
   ApplicationData = 23,
   Heartbeat = 24,  // RFC 6520 (TLS 1.3)
};

enum SizeLimits : size_t {
   TLS_HEADER_SIZE = 5,
   TLS_HANDSHAKE_HEADER_SIZE = 4,
   TLS12_AEAD_AAD_SIZE = 13,
   TLS13_AEAD_AAD_SIZE = 5,
   MAX_PLAINTEXT_SIZE = 16 * 1024,
   MAX_COMPRESSED_SIZE = MAX_PLAINTEXT_SIZE + 1024,
   MAX_CIPHERTEXT_SIZE = MAX_COMPRESSED_SIZE + 1024,
   MAX_AEAD_EXPANSION_SIZE_TLS13 = 255,
   MAX_CIPHERTEXT_SIZE_TLS13 = MAX_PLAINTEXT_SIZE + MAX_AEAD_EXPANSION_SIZE_TLS13 + 1
};

enum class HandshakeType : uint8_t {
   HelloRequest = 0,
   ClientHello = 1,
   ServerHello = 2,
   HelloVerifyRequest = 3,
   NewSessionTicket = 4,  // RFC 5077

   EndOfEarlyData = 5,       // RFC 8446 (TLS 1.3)
   EncryptedExtensions = 8,  // RFC 8446 (TLS 1.3)

   Certificate = 11,
   ServerKeyExchange = 12,
   CertificateRequest = 13,
   ServerHelloDone = 14,
   CertificateVerify = 15,
   ClientKeyExchange = 16,
   Finished = 20,

   KeyUpdate = 24,  // RFC 8446 (TLS 1.3)

   HelloRetryRequest = 253,  // Not a wire value (HRR appears as an ordinary Server Hello)
   HandshakeCCS = 254,       // Not a wire value (TLS 1.3 uses this value for 'message_hash' -- RFC 8446 4.4.1)
   None = 255                // Null value
};

std::string toString(const RecordType type);

std::string toString(const HandshakeType type);

enum class VersionCode : std::uint16_t
{
    SSLv2_0 = SSL2_VERSION,
    SSLv3_0 = SSL3_VERSION,
    TLSv1_0 = TLS1_VERSION,
    TLSv1_1 = TLS1_1_VERSION,
    TLSv1_2 = TLS1_2_VERSION,
    TLSv1_3 = TLS1_3_VERSION
};

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
DEFINE_CUSTOM_UNIQUE_PTR(EvpPkeyPtr, EVP_PKEY, EVP_PKEY_free);
DEFINE_CUSTOM_UNIQUE_PTR(EvpPkeyCtxPtr, EVP_PKEY_CTX, EVP_PKEY_CTX_free);
DEFINE_CUSTOM_UNIQUE_PTR(EvpCipherPtr, EVP_CIPHER, EVP_CIPHER_free);
DEFINE_CUSTOM_UNIQUE_PTR(EvpCipherCtxPtr, EVP_CIPHER_CTX, EVP_CIPHER_CTX_free);
DEFINE_CUSTOM_UNIQUE_PTR(EvpMdPtr, EVP_MD, EVP_MD_free);
DEFINE_CUSTOM_UNIQUE_PTR(EvpMdCtxPtr, EVP_MD_CTX, EVP_MD_CTX_free);
DEFINE_CUSTOM_UNIQUE_PTR(EvpKdfPtr, EVP_KDF, EVP_KDF_free);
DEFINE_CUSTOM_UNIQUE_PTR(EvpKdfCtxPtr, EVP_KDF_CTX, EVP_KDF_CTX_free);
DEFINE_CUSTOM_UNIQUE_PTR(EvpMacPtr, EVP_MAC, EVP_MAC_free);
DEFINE_CUSTOM_UNIQUE_PTR(EvpMacCtxPtr, EVP_MAC_CTX, EVP_MAC_CTX_free);

inline void OSSL_STORE_CTX_free(OSSL_STORE_CTX* ctx)
{
    OSSL_STORE_close(ctx);
}

DEFINE_CUSTOM_UNIQUE_PTR(StoreCtxPtr, OSSL_STORE_CTX, OSSL_STORE_CTX_free);
DEFINE_CUSTOM_UNIQUE_PTR(StoreInfoPtr, OSSL_STORE_INFO, OSSL_STORE_INFO_free);

} // namespace snet::tls