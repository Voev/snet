#pragma once
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <snet/crypto/exception.hpp>
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/bio.hpp>

#include <casket/utils/exception.hpp>

namespace snet::crypto
{

class CertRequest
{
public:
    static inline X509ReqPtr deepCopy(X509Req* csr)
    {
        return X509ReqPtr{X509_REQ_dup(csr)};
    }

    static inline CertReqVersion version(X509Req* csr)
    {
        long value = X509_REQ_get_version(csr);
        switch (value)
        {
        case static_cast<long>(CertReqVersion::V1):
            return static_cast<CertReqVersion>(value);
        default:
            throw casket::RuntimeError("Unsupported version of request for certificate: {}", std::to_string(value));
        }
    }

    static inline X509NamePtr subjectName(X509Req* csr)
    {
        auto name = X509_REQ_get_subject_name(csr);
        ThrowIfTrue(name == nullptr);

        auto result = X509_NAME_dup(name);
        ThrowIfTrue(result == nullptr);

        return X509NamePtr{result};
    }

    static inline KeyPtr publicKey(X509Req* csr)
    {
        auto result = X509_REQ_get_pubkey(csr);
        ThrowIfTrue(result == nullptr);

        return KeyPtr{result};
    }

    static inline CertExtOwningStackPtr extensions(X509Req* csr)
    {
        return CertExtOwningStackPtr{X509_REQ_get_extensions(csr)};
    }

    static inline bool verify(X509Req* csr, Key* publicKey)
    {
        return 0 < X509_REQ_verify(csr, publicKey);
    }

    static inline X509ReqPtr fromBio(Bio* bio, Encoding inEncoding)
    {
        X509ReqPtr result;

        switch (inEncoding)
        {
        case Encoding::DER:
        {
            result.reset(d2i_X509_REQ_bio(bio, nullptr));
        }
        break;

        case Encoding::PEM:
        {
            result.reset(PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr));
        }
        break;

        default:
        {
            throw CryptoException(TranslateError(ERR_R_PASSED_INVALID_ARGUMENT), "Unsupported encoding type");
        }
        break;
        }

        if (!result)
        {
            throw CryptoException(GetLastError(), "Failed to parse request for certificate");
        }

        return result;
    }

    static inline void toBio(X509Req* csr, Bio* bio, Encoding encoding)
    {
        switch (encoding)
        {
        case Encoding::PEM:
        {
            ThrowIfFalse(PEM_write_bio_X509_REQ(bio, csr));
        }
        break;

        case Encoding::DER:
        {
            ThrowIfFalse(i2d_X509_REQ_bio(bio, csr));
        }
        break;

        default:
            throw CryptoException(TranslateError(ERR_R_PASSED_INVALID_ARGUMENT), "Unsupported encoding");
        }
    }

    static inline X509ReqPtr fromBase64(nonstd::string_view base64)
    {
        auto bio = BioTraits::createMemoryReader(base64);
        BioTraits::attach(bio, BioTraits::createBase64Filter());
        return fromBio(bio, Encoding::DER);
    }

    static inline std::string toBase64(X509Req* csr)
    {
        auto bio = BioTraits::createMemoryBuffer();
        BioTraits::attach(bio, BioTraits::createBase64Filter());
        toBio(csr, bio, Encoding::DER);
        BioTraits::flush(bio);
        return BioTraits::getMemoryDataAsString(bio);
    }
};

} // namespace snet::crypto
