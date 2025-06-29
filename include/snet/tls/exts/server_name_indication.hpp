#pragma once
#include <casket/nonstd/span.hpp>
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
    ///
    /// @return The extension code for server name indication.
    static ExtensionCode staticType();

    /// @brief Gets the type of the extension.
    ///
    /// @return The extension code for server name indication.
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
    size_t serialize(Side side, nonstd::span<uint8_t> output) const override;

    /// @brief Constructor with hostname.
    ///
    /// @param[in] hostname The server hostname.
    explicit ServerNameIndicator(std::string_view hostname);

    /// @brief Constructor with input byte buffer.
    ///
    /// @param[in] side Side (client or server).
    /// @param[in] input Input byte buffer.
    ///
    ServerNameIndicator(Side side, nonstd::span<const uint8_t> input);

    /// @brief Gets the server hostname.
    ///
    /// @return The server hostname.
    const std::string& getHostname() const;

private:
    std::string hostname_;
};

} // namespace snet::tls