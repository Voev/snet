#pragma once
#include <snet/tls/exts/extension.hpp>
#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

/// @brief Extended Master Secret Extension (RFC 7627).
class ExtendedMasterSecret final : public Extension
{
public:
    /// @brief Gets the static type of the extension.
    /// @return The extension code for Extended Master Secret.
    static ExtensionCode staticType();

    /// @brief Gets the type of the extension.
    /// @return The extension code for Extended Master Secret.
    ExtensionCode type() const override;

    /// @brief Checks if the extension should be encoded.
    /// @retval false Always returns false as this extension is always sent.
    bool empty() const override;

    /// @brief Serialize extension to bytes.
    ///
    /// @param[in] side Side (Client or Server).
    /// @param[in] output Buffer for encoding.
    ///
    /// @return Serialized bytes count.
    size_t serialize(Side side, std::span<uint8_t> output) const override;

    /// @brief Default constructor.
    ExtendedMasterSecret() = default;

    /// @brief Constructor with data reader and extension size.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    ExtendedMasterSecret(std::span<const uint8_t> input);
};

} // namespace snet::tls