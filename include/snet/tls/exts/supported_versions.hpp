#pragma once
#include <snet/tls/version.hpp>
#include <snet/tls/exts/extension.hpp>
#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

/// @brief Supported Versions extension (RFC 8446).
class SupportedVersions final : public Extension
{
public:
    /// @brief Gets the static type of the extension.
    /// @return The extension code for Supported Versions.
    static ExtensionCode staticType()
    {
        return ExtensionCode::SupportedVersions;
    }

    /// @brief Gets the type of the extension.
    /// @return The extension code for Supported Versions.
    ExtensionCode type() const override
    {
        return staticType();
    }

    /// @brief Checks if the extension should be encoded.
    /// @retval true If there are no supported versions.
    /// @retval false Otherwise.
    bool empty() const override
    {
        return versions_.empty();
    }

    /// @brief Constructor with a single protocol version.
    /// @param version The protocol version.
    SupportedVersions(ProtocolVersion version)
    {
        versions_.push_back(version);
    }

    /// @brief Constructor with data reader and extension size.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    /// @param from The side (client or server).
    SupportedVersions(utils::DataReader& reader, uint16_t extensionSize, Side from);

    size_t serialize(Side whoami, std::span<uint8_t> buffer) const;

    /// @brief Checks if the extension supports a specific protocol version.
    /// @param version The protocol version to check.
    /// @retval true If the version is supported.
    /// @retval false Otherwise.
    bool supports(ProtocolVersion version) const;

    /// @brief Gets the list of supported protocol versions.
    /// @return The list of supported protocol versions.
    const std::vector<ProtocolVersion>& versions() const
    {
        return versions_;
    }



private:
    std::vector<ProtocolVersion> versions_;
};

} // namespace snet::tls