#include <snet/crypto/cert_name_builder.hpp>
#include <snet/crypto/cert_builder.hpp>
#include <snet/crypto/cert_self_signed.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::crypto
{

X509CertPtr CertSelfSigned::generate(Key* privateKey, const std::string& dn, int days)
{
    CertBuilder certBuilder;

    certBuilder.setNotBefore(std::chrono::seconds(0));
    certBuilder.setNotAfter(std::chrono::hours(days * 24));

    BigNumPtr serial(BN_new());
    ThrowIfFalse(serial, "failed to create serial number");
    ThrowIfFalse(0 < BN_rand(serial, 64, 0, 0));
    certBuilder.setSerialNumber(serial.get());

    auto name = CertNameBuilder::fromString(dn);
    certBuilder.setSubjectName(name);
    certBuilder.setPublicKey(privateKey);

    certBuilder.selfSigned(privateKey);
    certBuilder.setVersion(CertVersion::V3);
    certBuilder.setIssuerName(name);
    certBuilder.addExtension(NID_subject_key_identifier, "hash");
    certBuilder.addExtension(NID_basic_constraints, "critical,CA:TRUE");
    certBuilder.addExtension(NID_key_usage, "critical,cRLSign,keyCertSign");

    return certBuilder.build();
}

} // namespace snet::cryptos