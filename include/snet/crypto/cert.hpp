#pragma once
#include <ctime>
#include <filesystem>

#include <openssl/evp.h>

#include <snet/crypto/pointers.hpp>
#include <snet/crypto/bio.hpp>

#include <casket/nonstd/string_view.hpp>
#include <casket/nonstd/span.hpp>

#include <snet/utils/bytes_to_number.hpp>

namespace snet::crypto
{

class Cert final
{
public:
    static X509CertPtr shallowCopy(X509Cert* cert);

    static X509CertPtr deepCopy(X509Cert* cert);

    static inline uint64_t computeHash(X509Cert* cert, const Hash* hash)
    {
        uint8_t digest[EVP_MAX_MD_SIZE] = {};
        uint32_t digestLength = 0;

        ThrowIfFalse(0 < X509_digest(cert, hash, digest, &digestLength));
        return BytesToNumber<uint64_t>(digest, digestLength);
    }

    static bool isEqual(const X509Cert* op1, const X509Cert* op2);

    //static bool isSelfSigned(X509Cert* cert, bool verifySignature) noexcept;

    static CertVersion version(X509Cert* cert);

    static X509NamePtr subjectName(X509Cert* cert);

    static X509NamePtr issuerName(X509Cert* cert);

    static BigNumPtr serialNumber(X509Cert* cert);

    static KeyPtr publicKey(X509Cert* cert);

    static std::time_t notBefore(X509Cert* cert);

    static std::time_t notAfter(X509Cert* cert);

    static X509CertPtr fromStorage(std::string_view uri);

    static X509CertPtr fromFile(const std::filesystem::path& path);

    static X509CertPtr fromBio(Bio* bio, Encoding encoding = Encoding::PEM);

    static void toBio(X509Cert* cert, Bio* bio, Encoding encoding = Encoding::PEM);

    static X509CertPtr fromBuffer(nonstd::span<const uint8_t> input);

    static int toBuffer(OSSL_CONST_COMPAT X509Cert* cert, nonstd::span<uint8_t> output);

    static inline X509CertPtr fromBase64(nonstd::string_view base64)
    {
        auto bio = BioTraits::createMemoryReader(base64);
        BioTraits::attach(bio, BioTraits::createBase64Filter());
        return fromBio(bio, Encoding::DER);
    }

    static inline std::string toBase64(X509Cert* cert)
    {
        auto bio = BioTraits::createMemoryBuffer();
        BioTraits::attach(bio, BioTraits::createBase64Filter());
        toBio(cert, bio, Encoding::DER);
        BioTraits::flush(bio);
        return BioTraits::getMemoryDataAsString(bio);
    }
};

} // namespace snet::crypto