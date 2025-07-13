#include <cstring>
#include <openssl/store.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <snet/crypto/cert.hpp>
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

namespace snet::crypto::cert
{

CertPtr shallowCopy(Cert* cert)
{
    if (cert)
    {
        crypto::ThrowIfFalse(0 < X509_up_ref(cert));
        return CertPtr{cert};
    }
    return nullptr;
}

CertPtr deepCopy(Cert* cert)
{
    return CertPtr(X509_dup(cert));
}

bool isEqual(const Cert* op1, const Cert* op2)
{
    int res = X509_cmp(op1, op2);
    crypto::ThrowIfTrue(res == -2, "X509_cmp returned error");
    return res == 0;
}

CertVersion version(Cert* cert)
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

CertNamePtr subjectName(Cert* cert)
{
    auto name = X509_get_subject_name(cert);
    crypto::ThrowIfTrue(name == nullptr);

    auto result = X509_NAME_dup(name);
    crypto::ThrowIfTrue(result == nullptr);

    return CertNamePtr{result};
}

CertNamePtr issuerName(Cert* cert)
{
    auto name = X509_get_issuer_name(cert);
    crypto::ThrowIfTrue(name == nullptr);

    auto result = X509_NAME_dup(name);
    crypto::ThrowIfTrue(result == nullptr);

    return CertNamePtr{result};
}

BigNumPtr serialNumber(Cert* cert)
{
    Asn1Integer* sn = X509_get_serialNumber(cert);
    crypto::ThrowIfTrue(sn == nullptr);

    BigNumPtr result{ASN1_INTEGER_to_BN(sn, NULL)};
    crypto::ThrowIfTrue(result == nullptr);
    return result;
}

KeyPtr publicKey(Cert* cert)
{
    auto result = X509_get_pubkey(cert);
    crypto::ThrowIfTrue(result == nullptr);

    return KeyPtr{result};
}

std::time_t notBefore(Cert* cert)
{
    const Asn1Time* asn1Time = X509_get0_notBefore(cert);
    crypto::ThrowIfTrue(asn1Time == nullptr);

    return asn1TimeToEpoch(asn1Time);
}

std::time_t notAfter(Cert* cert)
{
    const Asn1Time* asn1Time = X509_get0_notAfter(cert);
    crypto::ThrowIfTrue(asn1Time == nullptr);

    return asn1TimeToEpoch(asn1Time);
}

CertPtr fromStorage(std::string_view uri)
{
    auto storeLoader = StoreLoader(uri, nullptr, nullptr);
    auto storeInfo = storeLoader.load(OSSL_STORE_INFO_CERT);
    auto result = CertPtr{OSSL_STORE_INFO_get1_CERT(storeInfo)};
    crypto::ThrowIfTrue(result == nullptr);

    return result;
}

CertPtr fromFile(const std::filesystem::path& path)
{
    return fromStorage("file:" + std::filesystem::absolute(path).string());
}

CertPtr fromBio(Bio* bio, Encoding encoding)
{
    CertPtr result;

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

void toBio(Cert* cert, Bio* bio, Encoding encoding)
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

} // namespace snet::crypto::cert

namespace snet::crypto
{

CertPtr CertFromMemory(nonstd::span<const uint8_t> memory)
{
    const unsigned char* ptr = memory.data();
    return CertPtr{d2i_X509(nullptr, &ptr, static_cast<long>(memory.size_bytes()))};
}

} // namespace snet::crypto