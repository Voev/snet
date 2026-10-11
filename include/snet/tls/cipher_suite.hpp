#pragma once
#include <string>
#include <cstdint>
#include <cassert>

#include <snet/crypto/typedefs.hpp>
#include <snet/crypto/hash_traits.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/version.hpp>

#include <casket/nonstd/string_view.hpp>

namespace snet::tls
{

using CipherSuite = SSL_CIPHER;

inline uint16_t CipherSuiteGetID(const CipherSuite* suite) noexcept
{
    assert(suite != nullptr && "invalid cipher suite");
    return SSL_CIPHER_get_protocol_id(suite);
}

inline std::uint32_t CipherSuiteGetKeySize(const CipherSuite* suite) noexcept
{
    assert(suite != nullptr && "invalid cipher suite");
    return SSL_CIPHER_get_bits(suite, nullptr) / 8;
}

inline nonstd::string_view CipherSuiteGetCipherName(const CipherSuite* suite) noexcept
{
    assert(suite != nullptr && "invalid cipher suite");
    auto cipherNid = SSL_CIPHER_get_cipher_nid(suite);
    return OBJ_nid2sn(cipherNid);
}

inline nonstd::string_view CipherSuiteGetHmacDigestName(const CipherSuite* suite) noexcept
{
    assert(suite != nullptr && "invalid cipher suite");
    auto digestNid = SSL_CIPHER_get_digest_nid(suite);
    return digestNid != NID_undef ? OBJ_nid2sn(digestNid) : "";
}

inline const Hash* CipherSuiteGetHandshakeDigest(const CipherSuite* suite) noexcept
{
    assert(suite != nullptr && "invalid cipher suite");
    return SSL_CIPHER_get_handshake_digest(suite);
}

inline nonstd::string_view CipherSuiteGetHandshakeDigestName(const CipherSuite* suite) noexcept
{
    assert(suite != nullptr && "invalid cipher suite");
    return crypto::HashTraits::getName(CipherSuiteGetHandshakeDigest(suite));
}

inline int CipherSuiteGetKeyExchange(const CipherSuite* suite) noexcept
{
    assert(suite != nullptr && "invalid cipher suite");
    return SSL_CIPHER_get_kx_nid(suite);
}

inline int CipherSuiteGetAuth(const CipherSuite* suite) noexcept
{
    assert(suite != nullptr && "invalid cipher suite");
    return SSL_CIPHER_get_auth_nid(suite);
}

inline nonstd::string_view CipherSuiteGetName(const CipherSuite* suite) noexcept
{
    assert(suite != nullptr && "invalid cipher suite");
    return SSL_CIPHER_get_name(suite);
}

inline nonstd::string_view CipherSuiteGetVersion(const CipherSuite* suite) noexcept
{
    assert(suite != nullptr && "invalid cipher suite");
    return SSL_CIPHER_get_version(suite);
}

inline bool CipherSuiteIsAEAD(const CipherSuite* suite) noexcept
{
    assert(suite != nullptr && "invalid cipher suite");
    return SSL_CIPHER_is_aead(suite);
}

} // namespace snet::tls