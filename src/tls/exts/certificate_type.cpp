#include <snet/tls/exts/certificate_type.hpp>
#include <snet/utils/contains.hpp>
#include <snet/utils/data_writer.hpp>
#include <snet/utils/data_reader.hpp>

#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::tls
{

std::string CertificateTypeToString(CertificateType type)
{
    switch (type)
    {
    case CertificateType::X509:
        return "X509";
    case CertificateType::RawPublicKey:
        return "RawPublicKey";
    }

    return "Unknown";
}

CertificateType CertificateTypeFromString(const std::string& typeStr)
{
    if (typeStr == "X509")
    {
        return CertificateType::X509;
    }
    else if (typeStr == "RawPublicKey")
    {
        return CertificateType::RawPublicKey;
    }
    else
    {
        throw RuntimeError("unknown certificate type: {}", typeStr);
    }
}

CertificateTypeBase::CertificateTypeBase(std::vector<CertificateType> supportedCertTypes)
    : certTypes_(std::move(supportedCertTypes))
    , from_(Side::Client)
{
    ThrowIfFalse(certTypes_.empty(), "at least one certificate type must be supported");
}

CertificateTypeBase::CertificateTypeBase(const CertificateTypeBase& certificateTypeFromClient,
                                         const std::vector<CertificateType>& serverPreference)
    : from_(Side::Server)
{
    for (const auto serverSupportedCertType : serverPreference)
    {
        if (contains(certificateTypeFromClient.certTypes_, serverSupportedCertType))
        {
            certTypes_.push_back(serverSupportedCertType);
            return;
        }
    }

    throw RuntimeError("failed to agree on CertificateType");
}

CertificateTypeBase::CertificateTypeBase(Side side, cpp::span<const uint8_t> input)
    : from_(side)
{
    utils::DataReader reader("certificate_type extension", input);

    if (side == Side::Client)
    {
        const auto typeBytes = reader.get_tls_length_value(1);
        ThrowIfTrue(reader.remaining_bytes() != typeBytes.size(), "certificate type extension had inconsistent length");

        std::transform(typeBytes.begin(), typeBytes.end(), std::back_inserter(certTypes_),
                       [](const auto typeByte) { return static_cast<CertificateType>(typeByte); });
    }
    else
    {
        const auto typeByte = reader.get_byte();
        ThrowIfFalse(typeByte == 0 || typeByte == 2, "malformed certificate type");
        certTypes_.push_back(static_cast<CertificateType>(typeByte));
    }

    reader.assert_done();
}

size_t CertificateTypeBase::serialize(Side whoami, cpp::span<uint8_t> buffer) const
{
    if (whoami == Side::Client)
    {
        std::vector<uint8_t> typeBytes(certTypes_.size());
        std::transform(certTypes_.begin(), certTypes_.end(), std::back_inserter(typeBytes),
                       [](const auto type) { return static_cast<uint8_t>(type); });

        return append_length_and_value(buffer, typeBytes.data(), typeBytes.size(), 1);
    }
    else
    {
        ThrowIfTrue(buffer.size_bytes() < 1, "buffer is too small");
        buffer[0] = static_cast<uint8_t>(certTypes_.front());
        return 1;
    }
}

void CertificateTypeBase::validateSelection(const CertificateTypeBase& fromServer) const
{
    ThrowIfFalse(from_ == Side::Client, "invalid from");
    ThrowIfFalse(fromServer.from_ == Side::Server, "invalid fromServer");

    if (!contains(certTypes_, fromServer.selectedCertificateType()))
    {
        throw RuntimeError("selected certificate type was not offered: {}",
                           CertificateTypeToString(fromServer.selectedCertificateType()));
    }
}

CertificateType CertificateTypeBase::selectedCertificateType() const
{
    ThrowIfFalse(from_ == Side::Server, "invalid argument");
    ThrowIfFalse(certTypes_.size() == 1, "invalid certificate type");
    return certTypes_.front();
}

ClientCertificateType::ClientCertificateType(const ClientCertificateType& cct)
    : CertificateTypeBase(cct)
{
}

ExtensionCode ClientCertificateType::staticType()
{
    return ExtensionCode::ClientCertificateType;
}

ExtensionCode ClientCertificateType::type() const
{
    return staticType();
}

ServerCertificateType::ServerCertificateType(const ServerCertificateType& sct)
    : CertificateTypeBase(sct)
{
}

ExtensionCode ServerCertificateType::staticType()
{
    return ExtensionCode::ServerCertificateType;
}

ExtensionCode ServerCertificateType::type() const
{
    return staticType();
}

} // namespace snet::tls