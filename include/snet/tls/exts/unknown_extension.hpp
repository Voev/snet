#pragma once
#include <vector>
#include <snet/tls/exts/extension.hpp>
#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

/// @brief Unknown extensions are deserialized as this type.
class UnknownExtension final : public Extension
{
public:
    /// @brief Gets the type of the extension.
    /// @return The extension code.
    ExtensionCode type() const override;

    /// @brief Checks if the extension should be encoded.
    /// @retval false Always returns false as this extension is always sent.
    bool empty() const override;

    /// @brief Serialize extension to bytes.
    ///
    /// @param[in] side Side (Client or Server).
    /// @param[in] buffer Buffer for encoding.
    ///
    /// @return Serialized bytes count.
    size_t serialize(Side side, std::span<uint8_t> buffer) const override;

    /// @brief Constructor with extension code, data reader, and extension size.
    /// @param type The extension code.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    UnknownExtension(ExtensionCode type, std::span<const uint8_t> input);

    /// @brief Gets the value of the unknown extension.
    /// @return The value of the unknown extension.
    const std::vector<uint8_t>& value();

private:
    ExtensionCode type_;
    std::vector<uint8_t> value_;
};

} // namespace snet::tls