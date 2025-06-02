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

    case ExtensionCode::AppLayerProtocolNegotiation:
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

} // namespace snet::tls