#pragma once

#include <chrono>
#include <string_view>

#include <snet/crypto/pointers.hpp>
#include <snet/utils/noncopyable.hpp>

namespace snet::crypto
{

class CertBuilder final : utils::NonCopyable
{
public:
    CertBuilder();

    ~CertBuilder() noexcept;

    void reset();

    CertBuilder& setVersion(CertVersion version);

    CertBuilder& setSubjectName(const CertName* name);

    CertBuilder& setSubjectName(const std::string& name);

    CertBuilder& setIssuerName(const CertName* name);

    CertBuilder& setIssuerName(const std::string& name);

    CertBuilder& setPublicKey(Key* publicKey);

    CertBuilder& setSerialNumber(const Asn1Integer* serialNumber);

    CertBuilder& setSerialNumber(const BigNum* serialNumber);

    CertBuilder& setNotBefore(const Asn1Time* time);

    CertBuilder& setNotBefore(std::chrono::seconds offsetSec);

    CertBuilder& setNotBefore(std::chrono::years offsetYears);

    CertBuilder& setNotAfter(const Asn1Time* time);

    CertBuilder& setNotAfter(std::chrono::seconds offsetSec);

    CertBuilder& setNotAfter(std::chrono::years offsetYears);

    CertBuilder& addExtension(CertExt* ext);

    CertBuilder& addExtension(int extNid, std::string_view value);

    CertBuilder& addExtension(std::string_view name, std::string_view value);

    CertBuilder& signedBy(Key* issuerPrivateKey, Cert* issuerCert);

    CertBuilder& selfSigned(Key* subjectPrivateKey);

    CertPtr build();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace snet::crypto