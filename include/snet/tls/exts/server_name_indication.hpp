#pragma once
#include <string>
#include <string_view>
#include <snet/tls/exts/extension.hpp>
#include <snet/utils/data_reader.hpp>

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

    /// @brief Constructor with hostname.
    /// @param hostname The server hostname.
    explicit ServerNameIndicator(std::string_view hostname);

    /// @brief Constructor with data reader and extension size.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    ServerNameIndicator(utils::DataReader& reader, uint16_t extensionSize);

    /// @brief Gets the server hostname.
    /// @return The server hostname.
    std::string host_name() const;

    /// @brief Checks if the extension is empty.
    /// @retval false Always returns false as this extension is always sent.
    bool empty() const override;

    size_t serialize(Side whoami, std::span<uint8_t> buffer) const override;

private:
    std::string hostname_;
};

} // namespace snet::tls