#pragma once
#include <ctime>
#include <string_view>
#include <filesystem>
#include <snet/crypto/pointers.hpp>
#include <casket/nonstd/span.hpp>

namespace snet::crypto
{

class Cert final
{
public:
    static X509CertPtr shallowCopy(X509Cert* cert);

    static X509CertPtr deepCopy(X509Cert* cert);

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
};

} // namespace snet::crypto