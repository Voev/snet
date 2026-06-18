#pragma once
#include <ctime>
#include <filesystem>

#include <openssl/evp.h>

#include <snet/crypto/pointers.hpp>
#include <snet/crypto/bio.hpp>
#include <snet/crypto/cert_name.hpp>

#include <snet/utils/time.hpp>

#include <casket/nonstd/string_view.hpp>
#include <casket/nonstd/span.hpp>
#include <casket/nonstd/optional.hpp>

namespace snet::crypto
{

class Cert final
{
public:
    static X509CertPtr shallowCopy(X509Cert* cert);

    static X509CertPtr deepCopy(X509Cert* cert);

    static bool isEqual(const X509Cert* op1, const X509Cert* op2);

    // static bool isSelfSigned(X509Cert* cert, bool verifySignature) noexcept;

    static CertVersion version(X509Cert* cert);

    static inline std::string subjectNameString(const X509Cert* cert)
    {
        auto subjectName = X509_get_subject_name(cert);
        return CertName::toString(subjectName);
    }

    static X509NamePtr subjectName(X509Cert* cert);

    static X509NamePtr issuerName(X509Cert* cert);

    static inline std::string issuerNameString(const X509Cert* cert)
    {
        auto issuerName = X509_get_issuer_name(cert);
        return CertName::toString(issuerName);
    }

    static BigNumPtr serialNumber(X509Cert* cert);

    static inline std::string serialNumberString(X509Cert* cert)
    {
        auto bio = BioTraits::createMemoryBuffer();
        BN_print(bio, serialNumber(cert));
        return BioTraits::getMemoryDataAsString(bio);
    }

    static KeyPtr publicKey(X509Cert* cert);

    static std::time_t notBefore(X509Cert* cert);

    static std::time_t notAfter(X509Cert* cert);

    static inline SystemTimePoint notBeforeTimePoint(X509Cert* cert)
    {
        auto time = notBefore(cert);
        return SystemClock::from_time_t(time);
    }

    static inline SystemTimePoint notAfterTimePoint(X509Cert* cert)
    {
        auto time = notAfter(cert);
        return SystemClock::from_time_t(time);
    }

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