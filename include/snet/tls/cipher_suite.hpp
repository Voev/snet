#pragma once
#include <snet/tls/types.hpp>
#include <snet/utils/singleton.hpp>

#include <span>
#include <string>
#include <string_view>
#include <cstdint>

namespace snet::tls
{

/// @brief TLS key exchange algorithms
enum class KexAlg
{
    Unknown,   ///< Unknown algorithm
    Null,      ///< Null algorithm
    Any,       ///< Any algorithm
    PSK,       ///< Pre-Shared Key
    SRP,       ///< Secure Remote Password
    RSA,       ///< RSA (Rivest-Shamir-Adleman)
    RSA_PSK,   ///< RSA (Rivest-Shamir-Adleman) with Pre-Shared Key
    DHE,       ///< Diffie-Hellman ephemeral
    DHE_PSK,   ///< Diffie-Hellman epehemral with Pre-Shared Key
    ECDHE,     ///< Elliptic curve Diffie-Hellman ephemeral
    ECDHE_PSK, ///< ECDHE with Pre-Shared Key
    GOST,      ///<
    GOST18,    ///<
};

/// @brief TLS authentication algorithms
enum class AuthAlg
{
    Unknown,   ///< Unknown algorithm
    Null,      ///< Null algorithm
    Any,       ///< Any algorithm
    PSK,       ///< Pre-Shared Key
    SRP,       ///< Secure Remote Protocol
    RSA,       ///< RSA (Rivest-Shamir-Adleman)
    DSS,       ///< Digital Signature Standard
    ECDSA,     ///< Elliptic Curve Digital Signature Algorithm
    GOST_2001, ///< GOST R 34.10-2001
    GOST_2012, ///< GOST R 34.10-2012
};

/**
 * SSL/TLS symmetric encryption algorithms
 */
enum class EncAlg
{
    /** Null value */
    SSL_SYM_NULL,
    /** RC4_40 */
    SSL_SYM_RC4_40,
    /** RC4_128 */
    SSL_SYM_RC4_128,
    /** RC2_CBC_40 */
    SSL_SYM_RC2_CBC_40,
    /** IDEA_CBC */
    SSL_SYM_IDEA_CBC,
    /** DES40_CBC */
    SSL_SYM_DES40_CBC,
    /** DES_CBC */
    SSL_SYM_DES_CBC,
    /** 3DES_EDE_CBC */
    SSL_SYM_3DES_EDE_CBC,
    /** FORTEZZA_CBC */
    SSL_SYM_FORTEZZA_CBC,
    /** DES_CBC_40 */
    SSL_SYM_DES_CBC_40,
    /** AES_128_CBC */
    SSL_SYM_AES_128_CBC,
    /** AES_256_CBC */
    SSL_SYM_AES_256_CBC,
    /** CAMELLIA_128_CBC */
    SSL_SYM_CAMELLIA_128_CBC,
    /** CAMELLIA_128_GCM */
    SSL_SYM_CAMELLIA_128_GCM,
    /** CAMELLIA_256_GCM */
    SSL_SYM_CAMELLIA_256_GCM,
    /** RC4_56 */
    SSL_SYM_RC4_56,
    /** RC2_CBC_56 */
    SSL_SYM_RC2_CBC_56,
    /** GOST28147 */
    SSL_SYM_GOST28147,
    /** CAMELLIA_256_CBC */
    SSL_SYM_CAMELLIA_256_CBC,
    /** SEED_CBC */
    SSL_SYM_SEED_CBC,
    /** AES_128 */
    SSL_SYM_AES_128,
    /** AES_256 */
    SSL_SYM_AES_256,
    /** SSL_SYM_AES_128_GCM */
    SSL_SYM_AES_128_GCM,
    /** AES_256_GCM */
    SSL_SYM_AES_256_GCM,
    /** RC4_128_EXPORT40 */
    SSL_SYM_RC4_128_EXPORT40,
    /** RC2_CBC_128_CBC */
    SSL_SYM_RC2_CBC_128_CBC,
    /** IDEA_128_CBC */
    SSL_SYM_IDEA_128_CBC,
    /** DES_64_CBC */
    SSL_SYM_DES_64_CBC,
    /** DES_192_EDE3_CBC */
    SSL_SYM_DES_192_EDE3_CBC,
    /** RC4_64 */
    SSL_SYM_RC4_64,
    /** ARIA_128_CBC*/
    SSL_SYM_ARIA_128_CBC,
    /** ARIA_256_CBC */
    SSL_SYM_ARIA_256_CBC,
    /** ARIA_128_GCM */
    SSL_SYM_ARIA_128_GCM,
    /** ARIA_256_GCM */
    SSL_SYM_ARIA_256_GCM,
    /** CHACHA20_POLY1305 */
    SSL_SYM_CHACHA20_POLY1305,
    /** AES_128_CCM */
    SSL_SYM_AES_128_CCM,
    /** AES_128_CCM_8 */
    SSL_SYM_AES_128_CCM_8,
    /** Unknown algorithm */
    SSL_SYM_Unknown
};

/// @brief TLS MAC algorithms
enum class MACAlg
{
    Unknown,
    Null,
    MD5,
    SHA1,
    SHA256,
    SHA384,
    GOST_R3411_94,
    GOST_R3411_2012_256,
    GOST_R3411_2012_512,
    GOST_28147,
    GOST_28147_12,
    GOST_Magma,
    GOST_Kuznyechik,
};

class CipherSuite final
{
public:
    CipherSuite();

    ~CipherSuite() noexcept;

    explicit CipherSuite(std::string name, std::uint32_t id,
                         std::uint32_t strengthBits, std::uint32_t algBits,
                         KexAlg keyExAlg, AuthAlg authAlg, EncAlg symKeyAlg,
                         MACAlg MACAlg);

    KexAlg getKeyExchAlg() const;

    AuthAlg getAuthAlg() const;

    MACAlg getHashAlg() const;

    EncAlg getEncAlg() const;

    std::uint32_t getStrengthBits() const;

    std::uint32_t getAlgBits() const;

private:
    std::string name_;
    std::uint32_t id_;
    std::uint32_t strengthBits_; ///< Number of bits really used
    std::uint32_t algBits_;      ///< Number of bits for algorithm
    KexAlg kex_;
    AuthAlg auth_;
    EncAlg enc_;
    MACAlg mac_;
};

class CipherSuiteManager final : public utils::Singleton<CipherSuiteManager>
{
public:
    CipherSuiteManager();
    ~CipherSuiteManager() noexcept;

    CipherSuite getCipherSuiteById(std::span<const uint8_t> id);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace snet::tls