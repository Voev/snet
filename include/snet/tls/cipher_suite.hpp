#pragma once
#include <snet/tls/types.hpp>
#include <casket/utils/singleton.hpp>

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
    Null,
    /** RC4_40 */
    RC4_40,
    /** RC4_128 */
    RC4_128,
    /** RC2_CBC_40 */
    RC2_CBC_40,
    /** IDEA_CBC */
    IDEA_CBC,
    /** DES40_CBC */
    DES40_CBC,
    /** DES_CBC */
    DES_CBC,
    /** 3DES_EDE_CBC */
    TRIPLEDES_EDE_CBC,
    /** FORTEZZA_CBC */
    FORTEZZA_CBC,
    /** DES_CBC_40 */
    DES_CBC_40,
    /** AES_128_CBC */
    AES_128_CBC,
    /** AES_256_CBC */
    AES_256_CBC,
    /** CAMELLIA_128_CBC */
    CAMELLIA_128_CBC,
    /** CAMELLIA_128_GCM */
    CAMELLIA_128_GCM,
    /** CAMELLIA_256_GCM */
    CAMELLIA_256_GCM,
    /** RC4_56 */
    RC4_56,
    /** RC2_CBC_56 */
    RC2_CBC_56,
    /** GOST28147 */
    GOST28147,
    /** CAMELLIA_256_CBC */
    CAMELLIA_256_CBC,
    /** SEED_CBC */
    SEED_CBC,
    /** AES_128 */
    AES_128,
    /** AES_256 */
    AES_256,
    /** AES_128_GCM */
    AES_128_GCM,
    /** AES_256_GCM */
    AES_256_GCM,
    /** RC4_128_EXPORT40 */
    RC4_128_EXPORT40,
    /** RC2_CBC_128_CBC */
    RC2_CBC_128_CBC,
    /** IDEA_128_CBC */
    IDEA_128_CBC,
    /** DES_64_CBC */
    DES_64_CBC,
    /** DES_192_EDE3_CBC */
    DES_192_EDE3_CBC,
    /** RC4_64 */
    RC4_64,
    /** ARIA_128_CBC*/
    ARIA_128_CBC,
    /** ARIA_256_CBC */
    ARIA_256_CBC,
    /** ARIA_128_GCM */
    ARIA_128_GCM,
    /** ARIA_256_GCM */
    ARIA_256_GCM,
    /** CHACHA20_POLY1305 */
    CHACHA20_POLY1305,
    /** AES_128_CCM */
    AES_128_CCM,
    /** AES_128_CCM_8 */
    AES_128_CCM_8,
    /** Unknown algorithm */
    Unknown
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

    explicit CipherSuite(std::string name, std::uint32_t id, std::uint32_t strengthBits,
                         std::uint32_t algBits, KexAlg keyExAlg, AuthAlg authAlg,
                         std::string cipher, std::string digest, std::string handshakeDigest, bool aead);

    const std::string& name() const;

    std::uint32_t id() const;

    KexAlg getKeyExchAlg() const;

    AuthAlg getAuthAlg() const;

    const std::string& getDigestName() const;

    const std::string& getHandshakeDigest() const;

    const std::string& getCipherName() const;

    std::uint32_t getStrengthBits() const;

    std::uint32_t getAlgBits() const;

    bool isAEAD() const;

private:
    std::string name_;
    std::uint32_t id_;
    std::uint32_t strengthBits_; ///< Number of bits really used
    std::uint32_t algBits_;      ///< Number of bits for algorithm
    KexAlg kex_;
    AuthAlg auth_;
    std::string cipher_;
    std::string digest_;
    std::string handshakeDigest_;
    bool aead_;
};

class CipherSuiteManager final : public casket::utils::Singleton<CipherSuiteManager>
{
public:
    CipherSuiteManager();

    ~CipherSuiteManager() noexcept;

    CipherSuite getCipherSuiteById(uint32_t id);

    EvpKdfPtr fetchKdf(std::string_view algorithm);

    EvpMacPtr fetchMac(std::string_view algorithm);

    EvpMdPtr fetchDigest(std::string_view algorithm);

    EvpCipherPtr fetchCipher(std::string_view algorithm);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace snet::tls