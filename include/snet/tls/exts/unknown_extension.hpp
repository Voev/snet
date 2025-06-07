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
    ///
    /// @retval true Should be encoded.
    /// @retval false Otherwise.
    bool empty() const override;

    /// @brief Serialize extension to bytes.
    ///
    /// @param[in] side Side (Client or Server).
    /// @param[in] ouput Buffer for encoding.
    ///
    /// @return Serialized bytes count.
    size_t serialize(Side side, std::span<uint8_t> output) const override;

    /// @brief Constructor with extension code and input byte buffer.
    ///
    /// @param[in] type Extension code.
    /// @param[in] input Input byte buffer.
    ///
    UnknownExtension(ExtensionCode type, std::span<const uint8_t> input);

    /// @brief Gets the value of the unknown extension.
    ///
    /// @return The value of the unknown extension.
    const std::vector<uint8_t>& value();

private:
    ExtensionCode type_;
    std::vector<uint8_t> value_;
};

} // namespace snet::tls