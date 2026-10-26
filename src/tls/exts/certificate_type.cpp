#include <snet/tls/exts/certificate_type.hpp>
#include <casket/utils/exception.hpp>

namespace snet::tls
{

CertificateType certificateTypeFromString(const std::string& s)
{
    if (s == "X509" || s == "x509")
        return CertificateType::X509;
    if (s == "RawPublicKey" || s == "rawpublickey")
        return CertificateType::RawPublicKey;
    throw casket::RuntimeError("unknown CertificateType: " + s);
}

namespace detail
{

utils::DecodeError parseCertificateTypes(Side side, nonstd::span<const uint8_t> input,
                                         std::vector<CertificateType>& out) noexcept
{
    utils::DataReader reader("certificate_type extension", input);

    if (side == Side::Client)
    {
        const auto typeBytes = reader.get_span_length_and_value(1);
        if (!reader.ok())
            return reader.take_error();
        if (reader.remaining_bytes() != typeBytes.size())
            return utils::DecodeError::LengthOutOfRange;

        try
        {
            out.reserve(typeBytes.size());
            for (auto b : typeBytes)
                out.push_back(static_cast<CertificateType>(b));
        }
        catch (...)
        {
            out.clear();
            return utils::DecodeError::AllocationFailed;
        }
    }
    else
    {
        const auto b = reader.get_byte();
        if (!reader.ok())
            return reader.take_error();

        try
        {
            out.push_back(static_cast<CertificateType>(b));
        }
        catch (...)
        {
            return utils::DecodeError::AllocationFailed;
        }
    }

    reader.assert_done();
    return reader.take_error();
}

std::size_t serializeCertificateTypes(Side side, nonstd::span<const CertificateType> types,
                                      nonstd::span<uint8_t> output) noexcept
{
    if (side == Side::Client)
    {
        if (types.size() > 255)
            return 0;
        if (output.size_bytes() < 1 + types.size())
            return 0;
        output[0] = static_cast<uint8_t>(types.size());
        for (std::size_t i = 0; i < types.size(); ++i)
            output[1 + i] = static_cast<uint8_t>(types[i]);
        return 1 + types.size();
    }
    if (types.size() != 1)
        return 0;
    if (output.size_bytes() < 1)
        return 0;
    output[0] = static_cast<uint8_t>(types[0]);
    return 1;
}

} // namespace detail

ClientCertificateType::ClientCertificateType(const ClientCertificateType& fromClient,
                                             nonstd::span<const CertificateType> serverPreference)
{
    for (auto pref : serverPreference)
    {
        for (auto offered : fromClient.types())
        {
            if (pref == offered)
            {
                certTypes_.push_back(pref);
                return;
            }
        }
    }
    // No match: empty -> `empty()` == true, extension omitted.
}

utils::DecodeError ClientCertificateType::validateSelection(const ClientCertificateType& fromServer) const noexcept
{
    if (fromServer.certTypes_.size() != 1)
    {
        return utils::DecodeError::LengthOutOfRange;
    }

    const auto sel = fromServer.certTypes_.front();
    for (auto t : certTypes_)
    {
        if (t == sel)
        {
            return utils::DecodeError::None;
        }
    }
    return utils::DecodeError::LengthOutOfRange;
}

ServerCertificateType::ServerCertificateType(const ServerCertificateType& fromClient,
                                             nonstd::span<const CertificateType> serverPreference)
{
    for (auto pref : serverPreference)
    {
        for (auto offered : fromClient.types())
        {
            if (pref == offered)
            {
                certTypes_.push_back(pref);
                return;
            }
        }
    }
}

utils::DecodeError ServerCertificateType::validateSelection(const ServerCertificateType& fromServer) const noexcept
{
    if (fromServer.certTypes_.size() != 1)
    {
        return utils::DecodeError::LengthOutOfRange;
    }

    const auto sel = fromServer.certTypes_.front();
    for (auto t : certTypes_)
    {
        if (t == sel)
        {
            return utils::DecodeError::None;
        }
    }
    return utils::DecodeError::LengthOutOfRange;
}

} // namespace snet::tls