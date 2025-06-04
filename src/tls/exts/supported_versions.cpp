#include <snet/tls/exts/supported_versions.hpp>

#include <casket/utils/exception.hpp>

using namespace casket::utils;

namespace snet::tls
{

ExtensionCode SupportedVersions::staticType()
{
    return ExtensionCode::SupportedVersions;
}

ExtensionCode SupportedVersions::type() const
{
    return staticType();
}

bool SupportedVersions::empty() const
{
    return versions_.empty();
}

size_t SupportedVersions::serialize(Side side, std::span<uint8_t> output) const
{
    if (side == Side::Server)
    {
        ThrowIfTrue(output.size_bytes() < 2, "buffer is too small");
        ThrowIfTrue(versions_.size() != 1, "one version for server must be selected");
        output[0] = versions_[0].majorVersion();
        output[1] = versions_[0].minorVersion();
        return 2;
    }
    else
    {
        size_t bytesVersions = 2 * versions_.size();
        size_t i = 0;

        ThrowIfTrue(output.size_bytes() < bytesVersions + 1, "buffer is too small");
        output[i++] = static_cast<uint8_t>(bytesVersions);

        for (const auto& version : versions_)
        {
            output[i++] = version.majorVersion();
            output[i++] = version.minorVersion();
        }

        return i;
    }
}

SupportedVersions::SupportedVersions(ProtocolVersion version)
{
    versions_.push_back(version);
}

SupportedVersions::SupportedVersions(const std::vector<ProtocolVersion>& versions)
    : versions_(versions)
{
}

SupportedVersions::SupportedVersions(Side side, std::span<const uint8_t> input)
{
    utils::DataReader reader("supported_versions extension", input);

    if (side == Side::Server)
    {
        ThrowIfTrue(input.size() != 2, "server sent invalid supported_versions extension");
        versions_.push_back(ProtocolVersion(reader.get_uint16_t()));
    }
    else
    {
        auto versions = reader.get_range<uint16_t>(1, 1, 127);
        for (auto v : versions)
        {
            versions_.push_back(ProtocolVersion(v));
        }
        ThrowIfTrue(input.size() != 1 + 2 * versions.size(), "client sent invalid supported_versions extension");
    }

    reader.assert_done();
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

const std::vector<ProtocolVersion>& SupportedVersions::versions() const
{
    return versions_;
}

} // namespace snet::tls