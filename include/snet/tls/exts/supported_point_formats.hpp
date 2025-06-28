#pragma once
#include <vector>
#include <snet/tls/types.hpp>
#include <snet/tls/exts/extension.hpp>

namespace snet::tls
{

enum ECPointFormat : uint8_t
{
    UNCOMPRESSED = 0,
    ANSIX962_COMPRESSED_PRIME = 1,
    ANSIX962_COMPRESSED_CHAR2 = 2,
};

/// @brief Supported EC Point Formats.
class SupportedPointFormats final : public Extension
{
public:
    /// @brief Gets the static type of the extension.
    ///
    /// @return The extension code for server name indication.
    static ExtensionCode staticType();

    /// @brief Gets the type of the extension.
    /// @return The extension code for supported point formats.
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

    /// @brief Constructor with input byte buffer.
    ///
    /// @param[in] side Side (client or server).
    /// @param[in] input Input byte buffer.
    ///
    SupportedPointFormats(Side side, cpp::span<const uint8_t> input);

    /// @brief Constructor with EC point formats.
    ///
    /// @param[in] format EC point formats.
    SupportedPointFormats(const std::vector<ECPointFormat>& formats);

    /// @brief Return EC point formats.
    /// @return EC point formats.
    const std::vector<ECPointFormat>& getFormats() const;

private:
    std::vector<ECPointFormat> formats_;
};

} // namespace snet::tls