#include <iterator>
#include <snet/tls/extensions.hpp>
#include <snet/tls/types.hpp>

using namespace casket::utils;

namespace snet::tls
{

std::unique_ptr<Extension> makeExtension(std::span<const uint8_t> input, ExtensionCode code, const Side side)
{
    switch (code)
    {
    case ExtensionCode::ServerNameIndication:
        return std::make_unique<ServerNameIndicator>(side, input);

    case ExtensionCode::AppLayerProtocolNegotiation:
        return std::make_unique<ALPN>(side, input);

    case ExtensionCode::ClientCertificateType:
        return std::make_unique<ClientCertificateType>(side, input);

    case ExtensionCode::ServerCertificateType:
        return std::make_unique<ServerCertificateType>(side, input);

    case ExtensionCode::ExtendedMasterSecret:
        return std::make_unique<ExtendedMasterSecret>(input);

    case ExtensionCode::RecordSizeLimit:
        return std::make_unique<RecordSizeLimit>(side, input);

    case ExtensionCode::EncryptThenMac:
        return std::make_unique<EncryptThenMAC>(input);

    case ExtensionCode::SupportedVersions:
        return std::make_unique<SupportedVersions>(side, input);

    //case ExtensionCode::SafeRenegotiation:
    //    return std::make_unique<RenegotiationExtension>(side, input);

    default:
        break;
    }

    return std::make_unique<UnknownExtension>(code, input);
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

void Extensions::deserialize(Side side, std::span<const uint8_t> input)
{
    utils::DataReader reader("Extensions", input);

    const uint16_t allExtSize = reader.get_uint16_t();
    ThrowIfTrue(reader.remaining_bytes() != allExtSize, "bad extension size");

    while (reader.has_remaining())
    {
        const uint16_t extensionCode = reader.get_uint16_t();
        const uint16_t extensionSize = reader.get_uint16_t();

        auto extensionData = reader.get_span_fixed<uint8_t>(extensionSize);
        add(makeExtension(extensionData, static_cast<ExtensionCode>(extensionCode), side));
    }
    reader.assert_done();
}

bool Extensions::containsOtherThan(const std::set<ExtensionCode>& allowedExtensions,
                                   const bool allowUnknownExtensions) const
{
    const auto found = extensionTypes();

    std::vector<ExtensionCode> diff;
    std::set_difference(found.cbegin(), found.end(), allowedExtensions.cbegin(), allowedExtensions.cend(),
                        std::back_inserter(diff));

    if (allowUnknownExtensions)
    {
        // Go through the found unexpected extensions whether any of those
        // is known to this TLS implementation.
        const auto itr = std::find_if(diff.cbegin(), diff.cend(),
                                      [this](const auto ext_type)
                                      {
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
    const auto i =
        std::find_if(extensions_.begin(), extensions_.end(), [type](const auto& ext) { return ext->type() == type; });

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