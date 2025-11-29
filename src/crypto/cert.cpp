#include <cstring>
#include <openssl/store.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <snet/crypto/cert.hpp>
#include <snet/crypto/cert_name.hpp>
#include <snet/crypto/store_loader.hpp>

#include <snet/crypto/exception.hpp>
#include <snet/crypto/error_code.hpp>

using namespace snet::crypto;

namespace
{

time_t asn1TimeToEpoch(const Asn1Integer* asn1Time)
{
    std::tm tmTime;
    std::memset(&tmTime, 0, sizeof(tmTime));
    snet::crypto::ThrowIfFalse(ASN1_TIME_to_tm(asn1Time, &tmTime));

    time_t result = std::mktime(&tmTime);
    if (result == static_cast<time_t>(-1))
    {
        throw CryptoException(TranslateError(ERR_R_OPERATION_FAIL), "Cannot convert ASN1_TIME to epoch");
    }

    return result;
}

} // namespace

namespace snet::crypto
{

X509CertPtr Cert::shallowCopy(X509Cert* cert)
{
    if (cert)
    {
        crypto::ThrowIfFalse(0 < X509_up_ref(cert));
        return X509CertPtr{cert};
    }
    return nullptr;
}

X509CertPtr Cert::deepCopy(X509Cert* cert)
{
    return X509CertPtr{X509_dup(cert)};
}

bool Cert::isEqual(const X509Cert* a, const X509Cert* b)
{
    int res = X509_cmp(a, b);
    crypto::ThrowIfTrue(res == -2, "X509_cmp returned error");
    return res == 0;
}


/*bool Cert::isSelfSigned(X509Cert* cert, bool verifySignature) noexcept
{
    return X509_self_signed(cert, verifySignature);
}*/

CertVersion Cert::version(X509Cert* cert)
{
    long value = X509_get_version(cert);
    switch (value)
    {
    case static_cast<long>(CertVersion::V1):
    case static_cast<long>(CertVersion::V2):
    case static_cast<long>(CertVersion::V3):
        return static_cast<CertVersion>(value);
    default:
        throw CryptoException(TranslateError(ERR_R_PASSED_INVALID_ARGUMENT),
                              "Unsupported version of certificate: " + std::to_string(value));
    }
}

X509NamePtr Cert::subjectName(X509Cert* cert)
{
    auto name = X509_get_subject_name(cert);
    crypto::ThrowIfTrue(name == nullptr);

    auto result = CertName::deepCopy(name);
    crypto::ThrowIfTrue(result == nullptr);

    return result;
}

X509NamePtr Cert::issuerName(X509Cert* cert)
{
    auto name = X509_get_issuer_name(cert);
    crypto::ThrowIfTrue(name == nullptr);

    auto result = CertName::deepCopy(name);
    crypto::ThrowIfTrue(result == nullptr);

    return result;
}

BigNumPtr Cert::serialNumber(X509Cert* cert)
{
    Asn1Integer* sn = X509_get_serialNumber(cert);
    crypto::ThrowIfTrue(sn == nullptr);

    BigNumPtr result{ASN1_INTEGER_to_BN(sn, NULL)};
    crypto::ThrowIfTrue(result == nullptr);
    return result;
}

KeyPtr Cert::publicKey(X509Cert* cert)
{
    auto result = X509_get_pubkey(cert);
    crypto::ThrowIfTrue(result == nullptr);

    return KeyPtr{result};
}

std::time_t Cert::notBefore(X509Cert* cert)
{
    const Asn1Time* asn1Time = X509_get0_notBefore(cert);
    crypto::ThrowIfTrue(asn1Time == nullptr);

    return asn1TimeToEpoch(asn1Time);
}

std::time_t Cert::notAfter(X509Cert* cert)
{
    const Asn1Time* asn1Time = X509_get0_notAfter(cert);
    crypto::ThrowIfTrue(asn1Time == nullptr);

    return asn1TimeToEpoch(asn1Time);
}

X509CertPtr Cert::fromStorage(std::string_view uri)
{
    auto storeLoader = StoreLoader(uri, nullptr, nullptr);
    auto storeInfo = storeLoader.load(OSSL_STORE_INFO_CERT);
    auto result = X509CertPtr{OSSL_STORE_INFO_get1_CERT(storeInfo)};
    crypto::ThrowIfTrue(result == nullptr);

    return result;
}

X509CertPtr Cert::fromFile(const std::filesystem::path& path)
{
    return fromStorage("file:" + std::filesystem::absolute(path).string());
}

X509CertPtr Cert::fromBio(Bio* bio, Encoding encoding)
{
    X509CertPtr result;

    switch (encoding)
    {
    case Encoding::DER:
    {
        result.reset(d2i_X509_bio(bio, nullptr));
        break;
    }

    case Encoding::PEM:
    {
        result.reset(PEM_read_bio_X509(bio, nullptr, nullptr, nullptr));
        break;
    }

    default:
    {
        throw CryptoException(TranslateError(ERR_R_PASSED_INVALID_ARGUMENT), "Unsupported encoding");
    }
    break;
    }

    if (!result)
    {
        throw CryptoException(GetLastError(), "Failed to parse certificate");
    }

    return result;
}

void Cert::toBio(X509Cert* cert, Bio* bio, Encoding encoding)
{
    int ret{0};

    switch (encoding)
    {
    case Encoding::DER:
    {
        ret = i2d_X509_bio(bio, cert);
    }
    break;

    case Encoding::PEM:
    {
        ret = PEM_write_bio_X509(bio, cert);
    }
    break;

    default:
    {
        throw CryptoException(TranslateError(ERR_R_PASSED_INVALID_ARGUMENT), "Unsupported encoding");
    }
    break;
    }

    if (!ret)
    {
        throw CryptoException(GetLastError(), "Failed to save certificate");
    }
}

X509CertPtr Cert::fromBuffer(nonstd::span<const uint8_t> input)
{
    const unsigned char* ptr = input.data();
    return X509CertPtr{d2i_X509(nullptr, &ptr, static_cast<long>(input.size_bytes()))};
}

int Cert::toBuffer(OSSL_CONST_COMPAT X509Cert* cert, nonstd::span<uint8_t> output)
{
    unsigned char* ptr = output.data();
    return i2d_X509(cert, &ptr);

}

} // namespace snet::crypto