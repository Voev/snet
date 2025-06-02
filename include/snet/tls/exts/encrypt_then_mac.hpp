#pragma once
#include <snet/tls/exts/extension.hpp>
#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

/// @brief Encrypt-then-MAC Extension (RFC 7366).
class EncryptThenMAC final : public Extension
{
public:
    /// @brief Gets the static type of the extension.
    /// @return The extension code for Encrypt-then-MAC.
    static ExtensionCode staticType();

    /// @brief Gets the type of the extension.
    /// @return The extension code for Encrypt-then-MAC.
    ExtensionCode type() const override;

    /// @brief Default constructor.
    EncryptThenMAC() = default;
    
    /// @brief Constructor with data reader and extension size.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    EncryptThenMAC(utils::DataReader& reader, uint16_t extensionSize);
    
    size_t serialize(Side whoami, std::span<uint8_t> buffer) const override;

    /// @brief Checks if the extension should be encoded.
    /// @retval false Always returns false as this extension is always sent.
    bool empty() const override;
};

} // namespace snet::tls