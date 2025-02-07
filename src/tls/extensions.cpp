#include <iterator>
#include <snet/tls/extensions.hpp>
#include <snet/tls/types.hpp>

using namespace casket::utils;

namespace snet::tls
{

std::unique_ptr<Extension> makeExtension(utils::DataReader& reader, ExtensionCode code,
                                          const Side from, const HandshakeType messageType)
{

    (void)messageType;

    // This cast is safe because we read exactly a 16 bit length field for
    // the extension in Extensions::deserialize
    const uint16_t size = static_cast<uint16_t>(reader.remaining_bytes());
    switch (code)
    {
    case ExtensionCode::ServerNameIndication:
        return std::make_unique<ServerNameIndicator>(reader, size);

    case ExtensionCode::ApplicationLayerProtocolNegotiation:
        return std::make_unique<ALPN>(reader, size, from);

    case ExtensionCode::ClientCertificateType:
        return std::make_unique<ClientCertificateType>(reader, size, from);

    case ExtensionCode::ServerCertificateType:
        return std::make_unique<ServerCertificateType>(reader, size, from);

    case ExtensionCode::ExtendedMasterSecret:
        return std::make_unique<ExtendedMasterSecret>(reader, size);

    case ExtensionCode::RecordSizeLimit:
        return std::make_unique<RecordSizeLimit>(reader, size, from);

    case ExtensionCode::EncryptThenMac:
        return std::make_unique<EncryptThenMAC>(reader, size);

    case ExtensionCode::SupportedVersions:
        return std::make_unique<SupportedVersions>(reader, size, from);

    default:
        break;
    }

    return std::make_unique<UnknownExtension>(code, reader, size);
}

void Extensions::add(std::unique_ptr<Extension> extn)
{
    if (has(extn->type()))
    {
        throw std::runtime_error("cannot add the same extension twice: " +
                                 std::to_string(static_cast<uint16_t>(extn->type())));
    }

    extensions_.emplace_back(extn.release());
}

void Extensions::deserialize(utils::DataReader& reader, const Side from,
                             const HandshakeType messageType)
{
    if (reader.has_remaining())
    {
        const uint16_t all_extn_size = reader.get_uint16_t();

        if (reader.remaining_bytes() != all_extn_size)
        {
            throw std::runtime_error("Bad extension size");
        }

        while (reader.has_remaining())
        {
            const uint16_t extensionCode = reader.get_uint16_t();
            const uint16_t extensionSize = reader.get_uint16_t();

            const auto type = static_cast<ExtensionCode>(extensionCode);

            if (this->has(type))
            {
                throw std::runtime_error("Peer sent duplicated extensions");
            }

            // TODO offer a function on reader that returns a byte range as a reference
            // to avoid this copy of the extension data
            const std::vector<uint8_t> extn_data = reader.get_fixed<uint8_t>(extensionSize);
            utils::DataReader extn_reader("Extension", extn_data);
            this->add(makeExtension(extn_reader, type, from, messageType));
            extn_reader.assert_done();
        }
    }
}

bool Extensions::containsOtherThan(const std::set<ExtensionCode>& allowedExtensions,
                                     const bool allowUnknownExtensions) const
{
    const auto found = extensionTypes();

    std::vector<ExtensionCode> diff;
    std::set_difference(found.cbegin(), found.end(), allowedExtensions.cbegin(),
                        allowedExtensions.cend(), std::back_inserter(diff));

    if (allowUnknownExtensions)
    {
        // Go through the found unexpected extensions whether any of those
        // is known to this TLS implementation.
        const auto itr = std::find_if(diff.cbegin(), diff.cend(), [this](const auto ext_type) {
            const auto ext = get(ext_type);
            return ext;
        });

        // ... if yes, `contains_other_than` is true
        return itr != diff.cend();
    }

    return !diff.empty();
}

std::unique_ptr<Extension> Extensions::take(ExtensionCode type)
{
    const auto i = std::find_if(extensions_.begin(), extensions_.end(),
                                [type](const auto& ext) { return ext->type() == type; });

    std::unique_ptr<Extension> result;
    if (i != extensions_.end())
    {
        std::swap(result, *i);
        extensions_.erase(i);
    }

    return result;
}

std::set<ExtensionCode> Extensions::extensionTypes() const
{
    std::set<ExtensionCode> offers;
    std::transform(extensions_.cbegin(), extensions_.cend(), std::inserter(offers, offers.begin()),
                   [](const auto& ext) { return ext->type(); });
    return offers;
}

UnknownExtension::UnknownExtension(ExtensionCode type, utils::DataReader& reader,
                                   uint16_t extensionSize)
    : type_(type)
    , value_(reader.get_fixed<uint8_t>(extensionSize))
{
}

ServerNameIndicator::ServerNameIndicator(utils::DataReader& reader, uint16_t extensionSize)
{
    /*
     * This is used by the server to confirm that it knew the name
     */
    if (extensionSize == 0)
    {
        return;
    }

    uint16_t name_bytes = reader.get_uint16_t();

    if (name_bytes + 2 != extensionSize)
    {
        throw std::runtime_error("Bad encoding of SNI extension");
    }

    while (name_bytes)
    {
        uint8_t name_type = reader.get_byte();
        name_bytes--;

        if (name_type == 0)
        {
            // DNS
            hostname_ = reader.get_string(2, 1, 65535);
            name_bytes -= static_cast<uint16_t>(2 + hostname_.size());
        }
        else
        {
            // some other unknown name type, which we will ignore
            reader.discard_next(name_bytes);
            name_bytes = 0;
        }
    }
}

ALPN::ALPN(utils::DataReader& reader, uint16_t extensionSize, Side from)
{
    if (extensionSize == 0)
    {
        return; // empty extension
    }

    const uint16_t nameBytes = reader.get_uint16_t();

    size_t bytesRemaining = extensionSize - 2;

    if (nameBytes != bytesRemaining)
    {
        throw std::runtime_error("Bad encoding of ALPN extension, bad length field");
    }

    while (bytesRemaining)
    {
        const std::string p = reader.get_string(1, 0, 255);

        if (bytesRemaining < p.size() + 1)
        {
            throw std::runtime_error("Bad encoding of ALPN, length field too long");
        }

        if (p.empty())
        {
            throw std::runtime_error("Empty ALPN protocol not allowed");
        }

        bytesRemaining -= (p.size() + 1);

        protocols_.push_back(p);
    }

    // RFC 7301 3.1
    //    The "extension_data" field of the [...] extension is structured the
    //    same as described above for the client "extension_data", except that
    //    the "ProtocolNameList" MUST contain exactly one "ProtocolName".
    if (from == Side::Server && protocols_.size() != 1)
    {
        throw std::runtime_error("Server sent " + std::to_string(protocols_.size()) +
                                 " protocols in ALPN extension response");
    }
}

std::string ALPN::singleProtocol() const
{
    return protocols_.front();
}

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
        throw std::runtime_error("Unknown certificate type: " + typeStr);
    }
}

CertificateTypeBase::CertificateTypeBase(std::vector<CertificateType> supportedCertTypes)
    : certTypes_(std::move(supportedCertTypes))
    , from_(Side::Client)
{
    ThrowIfFalse(certTypes_.empty(), "at least one certificate type must be supported");
}

ClientCertificateType::ClientCertificateType(const ClientCertificateType& cct)
    : CertificateTypeBase(cct)
{
}

ServerCertificateType::ServerCertificateType(const ServerCertificateType& sct)
    : CertificateTypeBase(sct)
{
}

template <typename T>
bool contains(std::vector<T> const& v, T const& x)
{
    return std::find(v.begin(), v.end(), x) != v.end();
}

CertificateTypeBase::CertificateTypeBase(const CertificateTypeBase& certificateTypeFromClient,
                                         const std::vector<CertificateType>& serverPreference)
    : from_(Side::Server)
{
    // RFC 7250 4.2
    //    The server_CertificateType extension in the client hello indicates the
    //    types of certificates the client is able to process when provided by
    //    the server in a subsequent certificate payload. [...] With the
    //    server_CertificateType extension in the server hello, the TLS server
    //    indicates the certificate type carried in the Certificate payload.
    for (const auto serverSupportedCertType : serverPreference)
    {
        if (contains(certificateTypeFromClient.certTypes_, serverSupportedCertType))
        {
            certTypes_.push_back(serverSupportedCertType);
            return;
        }
    }

    // RFC 7250 4.2 (2.)
    //    The server supports the extension defined in this document, but
    //    it does not have any certificate type in common with the client.
    //    Then, the server terminates the session with a fatal alert of
    //    type "unsupported_certificate".
    throw std::runtime_error("Failed to agree on CertificateType");
}

CertificateTypeBase::CertificateTypeBase(utils::DataReader& reader, uint16_t extensionSize,
                                         Side from)
    : from_(from)
{
    if (extensionSize == 0)
    {
        throw std::runtime_error("Certificate type extension cannot be empty");
    }

    if (from == Side::Client)
    {
        const auto typeBytes = reader.get_tls_length_value(1);
        if (static_cast<size_t>(extensionSize) != typeBytes.size() + 1)
        {
            throw std::runtime_error("Certificate type extension had inconsistent length");
        }
        std::transform(
            typeBytes.begin(), typeBytes.end(), std::back_inserter(certTypes_),
            [](const auto typeByte) { return static_cast<CertificateType>(typeByte); });
    }
    else
    {
        // RFC 7250 4.2
        //    Note that only a single value is permitted in the
        //    server_CertificateType extension when carried in the server hello.
        if (extensionSize != 1)
        {
            throw std::runtime_error("Server's certificate type extension must be of length 1");
        }
        const auto typeByte = reader.get_byte();
        certTypes_.push_back(static_cast<CertificateType>(typeByte));
    }
}

void CertificateTypeBase::validateSelection(const CertificateTypeBase& fromServer) const
{
    ThrowIfFalse(from_ == Side::Client, "invalid from");
    ThrowIfFalse(fromServer.from_ == Side::Server, "invalid fromServer");

    // RFC 7250 4.2
    //    The value conveyed in the [client_]CertificateType extension MUST be
    //    selected from one of the values provided in the [client_]CertificateType
    //    extension sent in the client hello.
    if (!contains(certTypes_, fromServer.selectedCertificateType()))
    {
        throw std::runtime_error(
            format("Selected certificate type was not offered: {}",
                   CertificateTypeToString(fromServer.selectedCertificateType())));
    }
}

CertificateType CertificateTypeBase::selectedCertificateType() const
{
    ThrowIfFalse(from_ == Side::Server, "Invalid from_");
    ThrowIfFalse(certTypes_.size() == 1, "Invalid certificate type");
    return certTypes_.front();
}

ExtendedMasterSecret::ExtendedMasterSecret(utils::DataReader& /*unused*/, uint16_t extensionSize)
{
    if (extensionSize != 0)
    {
        throw std::runtime_error("Invalid extended_master_secret extension");
    }
}

EncryptThenMAC::EncryptThenMAC(utils::DataReader& /*unused*/, uint16_t extensionSize)
{
    if (extensionSize != 0)
    {
        throw std::runtime_error("Invalid encrypt_then_mac extension");
    }
}

SupportedVersions::SupportedVersions(utils::DataReader& reader, uint16_t extensionSize, Side from)
{
    if (from == Side::Server)
    {
        if (extensionSize != 2)
        {
            throw std::runtime_error("Server sent invalid supported_versions extension");
        }
        versions_.push_back(ProtocolVersion(reader.get_uint16_t()));
    }
    else
    {
        auto versions = reader.get_range<uint16_t>(1, 1, 127);

        for (auto v : versions)
        {
            versions_.push_back(ProtocolVersion(v));
        }

        if (extensionSize != 1 + 2 * versions.size())
        {
            throw std::runtime_error("Client sent invalid supported_versions extension");
        }
    }
}

bool SupportedVersions::supports(ProtocolVersion version) const
{
    for (auto v : versions_)
    {
        if (version == v)
        {
            return true;
        }
    }
    return false;
}

RecordSizeLimit::RecordSizeLimit(const uint16_t limit)
    : limit_(limit)
{
    ThrowIfFalse(limit >= 64, "RFC 8449 does not allow record size limits smaller than 64 bytes");
    ThrowIfFalse(limit <= MAX_PLAINTEXT_SIZE + 1 /* encrypted content type byte */,
                 "RFC 8449 does not allow record size limits larger than 2^14+1");
}

RecordSizeLimit::RecordSizeLimit(utils::DataReader& reader, uint16_t extensionSize, Side from)
{
    if (extensionSize != 2)
    {
        throw std::runtime_error("invalid record_size_limit extension");
    }

    limit_ = reader.get_uint16_t();

    // RFC 8449 4.
    //    This value is the length of the plaintext of a protected record.
    //    The value includes the content type and padding added in TLS 1.3 (that
    //    is, the complete length of TLSInnerPlaintext).
    //
    //    A server MUST NOT enforce this restriction; a client might advertise
    //    a higher limit that is enabled by an extension or version the server
    //    does not understand. A client MAY abort the handshake with an
    //    "illegal_parameter" alert.
    //
    // Note: We are currently supporting this extension in TLS 1.3 only, hence
    //       we check for the TLS 1.3 limit. The TLS 1.2 limit would not include
    //       the "content type byte" and hence be one byte less!
    if (limit_ > MAX_PLAINTEXT_SIZE + 1 /* encrypted content type byte */ && from == Side::Server)
    {
        throw std::runtime_error(
            "Server requested a record size limit larger than the protocol's maximum");
    }

    // RFC 8449 4.
    //    Endpoints MUST NOT send a "record_size_limit" extension with a value
    //    smaller than 64.  An endpoint MUST treat receipt of a smaller value
    //    as a fatal error and generate an "illegal_parameter" alert.
    if (limit_ < 64)
    {
        throw std::runtime_error("Received a record size limit smaller than 64 bytes");
    }
}

RenegotiationExtension::RenegotiationExtension(utils::DataReader& reader, uint16_t extensionSize)
    : renegData_(reader.get_range<uint8_t>(1, 0, 255))
{
    if (renegData_.size() + 1 != extensionSize)
    {
        throw std::runtime_error("Bad encoding for secure renegotiation extn");
    }
}

} // namespace snet::tls