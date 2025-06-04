#pragma once
#include <vector>
#include <snet/tls/types.hpp>
#include <snet/tls/exts/extension.hpp>

namespace snet::tls
{

/// @brief Renegotiation Indication Extension (RFC 5746).
class RenegotiationExtension final : public Extension
{
public:
    /// @brief Gets the static type of the extension.
    /// @return The extension code for Safe Renegotiation.
    static ExtensionCode staticType();

    /// @brief Gets the type of the extension.
    /// @return The extension code for Safe Renegotiation.
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
    RenegotiationExtension() = default;

    /// @brief Constructor with renegotiation data.
    /// @param renegData The renegotiation data.
    explicit RenegotiationExtension(const std::vector<uint8_t>& renegData);

    /// @brief Constructor with data reader and extension size.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    RenegotiationExtension(Side side, std::span<const uint8_t> input);

    /// @brief Gets the renegotiation information.
    /// @return The renegotiation information.
    const std::vector<uint8_t>& getRenegInfo() const;

private:
    std::vector<uint8_t> renegData_;
};

} // namespace snet::tls