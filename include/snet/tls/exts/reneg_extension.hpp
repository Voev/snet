#pragma once
#include <string>
#include <snet/tls/types.hpp>
#include <snet/tls/exts/extension.hpp>
#include <snet/utils/data_reader.hpp>

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

    /// @brief Default constructor.
    RenegotiationExtension() = default;

    /// @brief Constructor with renegotiation data.
    /// @param bits The renegotiation data.
    explicit RenegotiationExtension(const std::vector<uint8_t>& bits);

    /// @brief Constructor with data reader and extension size.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    RenegotiationExtension(utils::DataReader& reader, uint16_t extensionSize);

    size_t serialize(Side side, std::span<uint8_t> buffer) const override;

    /// @brief Gets the renegotiation information.
    /// @return The renegotiation information.
    const std::vector<uint8_t>& renegotiation_info() const;

    /// @brief Checks if the extension should be encoded.
    /// @retval false Always returns false as this extension is always sent.
    bool empty() const override;

private:
    std::vector<uint8_t> renegData_;
};

} // namespace snet::tls