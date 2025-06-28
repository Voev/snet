#pragma once
#include <snet/tls/exts/extension.hpp>

namespace snet::tls
{

/// @brief Extended Master Secret Extension (RFC 7627).
class ExtendedMasterSecret final : public Extension
{
public:
    /// @brief Gets the static type of the extension.
    ///
    /// @return The extension code for Extended Master Secret.
    static ExtensionCode staticType();

    /// @brief Gets the type of the extension.
    ///
    /// @return The extension code for Extended Master Secret.
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
    size_t serialize(Side side, cpp::span<uint8_t> output) const override;

    /// @brief Default constructor.
    ///
    ExtendedMasterSecret() = default;

    /// @brief Constructor with input byte buffer.
    ///
    /// @param[in] input Input byte buffer.
    ///
    ExtendedMasterSecret(cpp::span<const uint8_t> input);
};

} // namespace snet::tls