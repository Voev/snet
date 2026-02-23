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

/// @brief Enum representing the side (client or server).
enum class Side : uint8_t
{
    Client = 0,
    Server
};

/// @brief Enum representing the record type.
enum class RecordType : uint8_t
{
    Invalid = 0, ///< Invalid record type (RFC 8446 - TLS 1.3)
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24 ///< Heartbeat (RFC 6520 - TLS 1.3)
};

/// @brief Enum representing size limits for TLS.
enum SizeLimits : size_t
{
    TLS_HEADER_SIZE = 5,
    TLS_HANDSHAKE_HEADER_SIZE = 4,
    TLS_RANDOM_SIZE = 32,
    TLS_MASTER_SECRET_SIZE = 48,
    TLS_MAX_MAC_LENGTH = EVP_MAX_MD_SIZE,
    TLS_MAX_KEY_LENGTH = EVP_MAX_KEY_LENGTH,
    TLS_MAX_IV_LENGTH = EVP_MAX_IV_LENGTH,
    TLS12_AEAD_AAD_SIZE = 13,
    TLS12_AEAD_NONCE_SIZE = 12,
    TLS13_AEAD_AAD_SIZE = 5,
    TLS13_AEAD_NONCE_SIZE = 12,
    MAX_PLAINTEXT_SIZE = 16 * 1024,
    MAX_COMPRESSED_SIZE = MAX_PLAINTEXT_SIZE + 1024,
    MAX_CIPHERTEXT_SIZE_TLS12 = MAX_COMPRESSED_SIZE + 1024,
    MAX_AEAD_EXPANSION_SIZE_TLS13 = 255,
    MAX_CIPHERTEXT_SIZE_TLS13 = MAX_PLAINTEXT_SIZE + MAX_AEAD_EXPANSION_SIZE_TLS13 + 1,
    MAX_CIPHERTEXT_SIZE = MAX_CIPHERTEXT_SIZE_TLS13,
};

/// @brief Enum representing the handshake type.
enum class HandshakeType : uint8_t
{
    HelloRequestCode = 0,
    ClientHelloCode = 1,
    ServerHelloCode = 2,
    HelloVerifyRequestCode = 3,
    NewSessionTicketCode = 4, ///< RFC 5077

    EndOfEarlyDataCode = 5,      ///< RFC 8446 (TLS 1.3)
    EncryptedExtensionsCode = 8, ///< RFC 8446 (TLS 1.3)

    CertificateCode = 11,
    ServerKeyExchangeCode = 12,
    CertificateRequestCode = 13,
    ServerHelloDoneCode = 14,
    CertificateVerifyCode = 15,
    ClientKeyExchangeCode = 16,
    FinishedCode = 20,

    KeyUpdateCode = 24, ///< RFC 8446 (TLS 1.3)

    HelloRetryRequestCode = 253, ///< Not a wire value (HRR appears as an ordinary Server Hello)
    HandshakeCCSCode = 254,      ///< Not a wire value (TLS 1.3 uses this value for 'message_hash' -- RFC 8446 4.4.1)
    NoneCode = 255               ///< Null value
};

/// @brief Converts a RecordType to a string representation.
/// @param type The RecordType to convert.
/// @return The string representation of the RecordType.
std::string toString(const RecordType type);

/// @brief Converts a HandshakeType to a string representation.
/// @param type The HandshakeType to convert.
/// @return The string representation of the HandshakeType.
std::string toString(const HandshakeType type);

/// @brief Enum representing the verify mode.
enum class VerifyMode
{
    None = 0x00,
    Peer = 0x01,
    FailIfNoPeerCert = 0x02,
    ClientOnce = 0x04,
    PostHandhsake = 0x08
};

/// @brief Type alias for the verify callback function.
using VerifyCallback = int (*)(int, X509_STORE_CTX*);

/// @brief Enum representing the mode.
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

/// @brief Enum representing the session cache mode.
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

/// @brief Security level for TLS settings.
enum class SecurityLevel : int
{
    Level0 = 0,
    Level1,
    Level2,
    Level3,
    Level4,
    Level5,
};

DEFINE_CUSTOM_UNIQUE_PTR(SslPtr, SSL, SSL_free);
DEFINE_CUSTOM_UNIQUE_PTR(SslCtxPtr, SSL_CTX, SSL_CTX_free);
DEFINE_CUSTOM_UNIQUE_PTR(SslSessionPtr, SSL_SESSION, SSL_SESSION_free);

} // namespace snet::tls