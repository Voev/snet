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

DEFINE_CUSTOM_UNIQUE_PTR(SslPtr, SSL, SSL_free);
DEFINE_CUSTOM_UNIQUE_PTR(SslCtxPtr, SSL_CTX, SSL_CTX_free);

} // namespace snet::tls