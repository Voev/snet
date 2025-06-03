#pragma once
#include <snet/tls/exts/extension.hpp>
#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

/// @brief Record Size Limit (RFC 8449).
class RecordSizeLimit final : public Extension
{
public:
    /// @brief Gets the static type of the extension.
    /// @return The extension code for Record Size Limit.
    static ExtensionCode staticType();

    /// @brief Gets the type of the extension.
    /// @return The extension code for Record Size Limit.
    ExtensionCode type() const override;

    /// @brief Checks if the extension should be encoded.
    /// @retval true If the limit is 0.
    /// @retval false Otherwise.
    bool empty() const override;

    /// @brief Serialize extension to bytes.
    ///
    /// @param[in] side Side (Client or Server).
    /// @param[in] output Buffer for encoding.
    ///
    /// @return Serialized bytes count.
    size_t serialize(Side side, std::span<uint8_t> output) const override;

    /// @brief Constructor with record size limit.
    /// @param limit The record size limit.
    explicit RecordSizeLimit(uint16_t limit);

    /// @brief Constructor with data reader and extension size.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    /// @param from The side (client or server).
    RecordSizeLimit(Side side, std::span<const uint8_t> input);

    /// @brief Gets the record size limit.
    /// @return The record size limit.
    uint16_t limit() const;

private:
    uint16_t limit_;
};

} // namespace snet::tls