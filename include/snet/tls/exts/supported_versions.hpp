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
    ///
    /// @return The extension code for supported versions.
    static ExtensionCode staticType();

    /// @brief Gets the type of the extension.
    ///
    /// @return The extension code for Supported Versions.
    ExtensionCode type() const override;

    /// @brief Checks if the extension should be encoded.
    ///
    /// @retval true Should be encoded.
    /// @retval false Otherwise.
    bool empty() const override;

    /// @brief Serialize extension to bytes.
    ///
    /// @param[in] side Side (Client or Server).
    /// @param[in] output Buffer for encoding.
    ///
    /// @return Serialized bytes count.
    size_t serialize(Side side, std::span<uint8_t> output) const override;

    /// @brief Constructor with a single protocol version.
    ///
    /// @param[in] version The protocol version.
    SupportedVersions(ProtocolVersion version);

    /// @brief Constructor with multiple protocol versions.
    ///
    /// @param[in] versions The protocol versions.
    SupportedVersions(const std::vector<ProtocolVersion>& versions);

    /// @brief Constructor with input byte buffer.
    ///
    /// @param[in] side Side (client or server).
    /// @param[in] input Input byte buffer.
    ///
    SupportedVersions(Side side, std::span<const uint8_t> input);

    /// @brief Checks if the extension supports a specific protocol version.
    ///
    /// @param[in] version The protocol version to check.
    ///
    /// @retval true If the version is supported.
    /// @retval false Otherwise.
    bool supports(ProtocolVersion version) const;

    /// @brief Gets the list of supported protocol versions.
    ///
    /// @return The list of supported protocol versions.
    const std::vector<ProtocolVersion>& versions() const;

private:
    std::vector<ProtocolVersion> versions_;
};

} // namespace snet::tls