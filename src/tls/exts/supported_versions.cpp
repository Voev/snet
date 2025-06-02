#include <snet/tls/exts/supported_versions.hpp>

#include <casket/utils/exception.hpp>

using namespace casket::utils;

namespace snet::tls
{

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

size_t SupportedVersions::serialize(Side whoami, std::span<uint8_t> buffer) const
{
    if (whoami == Side::Server)
    {
        ThrowIfTrue(buffer.size_bytes() < 2, "buffer is too small");
        ThrowIfTrue(versions_.size() != 1, "one version for server must be selected");
        buffer[0] = versions_[0].majorVersion();
        buffer[1] = versions_[0].minorVersion();
        return 2;
    }
    else
    {
        size_t bytesVersions = 2 * versions_.size();
        size_t i = 0;

        ThrowIfTrue(buffer.size_bytes() < bytesVersions + 1, "buffer is too small");
        buffer[i++] = static_cast<uint8_t>(bytesVersions);

        for (const auto& version : versions_)
        {
            buffer[i++] = version.majorVersion();
            buffer[i++] = version.minorVersion();
        }

        return i;
    }
}

} // namespace snet::tls