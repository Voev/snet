#pragma once
#include <span>
#include <string>
#include <string_view>
#include <snet/tls/exts/extension.hpp>

namespace snet::tls
{

/// @brief Server Name Indicator extension (RFC 3546).
class ServerNameIndicator final : public Extension
{
public:
    /// @brief Gets the static type of the extension.
    /// @return The extension code for server name indication.
    static ExtensionCode staticType();

    /// @brief Gets the type of the extension.
    /// @return The extension code for server name indication.
    ExtensionCode type() const override;

    /// @brief Checks if the extension is empty.
    /// @retval false Always returns false as this extension is always sent.
    bool empty() const override;

    /// @brief Serialize extension to bytes.
    ///
    /// @param[in] side Side (Client or Server).
    /// @param[in] output Buffer for encoding.
    ///
    /// @return Serialized bytes count.
    size_t serialize(Side side, std::span<uint8_t> output) const override;

    /// @brief Constructor with hostname.
    /// @param hostname The server hostname.
    explicit ServerNameIndicator(std::string_view hostname);

    /// @brief Constructor with data reader and extension size.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    ServerNameIndicator(Side side, std::span<const uint8_t> input);

    /// @brief Gets the server hostname.
    /// @return The server hostname.
    const std::string& getHostname() const;

private:
    std::string hostname_;
};

} // namespace snet::tls