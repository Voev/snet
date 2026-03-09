#pragma once
#include <vector>
#include <casket/utils/exception.hpp>
#include <snet/crypto/group_params.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/exts/extension.hpp>
#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

/// @brief Parse a list of items from a byte buffer.
///
/// @tparam T Type of items to parse (must be constructible from uint16_t).
/// @param[in] input Byte span containing the encoded list.
/// @param[in] name Name of the list for error reporting.
///
/// @return Vector of parsed items.
template <class T>
inline std::vector<T> ParseListItems(nonstd::span<const uint8_t> input, const char* name)
{
    utils::DataReader reader(name, input);
    uint16_t length = reader.get_uint16_t();

    casket::ThrowIfTrue(length % 2 == 1 || length == 0, "Bad encoding {} extension");

    std::vector<T> schemes;
    schemes.reserve(length / 2);
    while (length)
    {
        schemes.emplace_back(reader.get_uint16_t());
        length -= 2;
    }

    return schemes;
}

/// @brief Supported Groups Extension (RFC 7919).
class SupportedGroups final : public Extension
{
public:
    /// @brief Get the static extension code for Supported Groups.
    ///
    /// @return The extension code value for Supported Groups.
    static ExtensionCode staticType()
    {
        return ExtensionCode::SupportedGroups;
    }

    /// @brief Get the extension type code.
    ///
    /// @return The extension type code for this instance.
    ExtensionCode type() const override
    {
        return staticType();
    }

    /// @brief Get all supported groups.
    ///
    /// @return Reference to the list of all groups.
    const std::vector<crypto::GroupParams>& groups() const
    {
        return groups_;
    }

    /// @brief Get the list of groups that are ECDH curves
    /// @return Vector containing only ECDH groups
    std::vector<crypto::GroupParams> getEcGroups() const
    {
        std::vector<crypto::GroupParams> ec;
        for (auto g : groups_)
        {
            if (g.isPureEccGroup())
            {
                ec.emplace_back(std::move(g));
            }
        }
        return ec;
    }

    /// @brief Get the list of groups in the FFDHE range (finite field groups).
    ///
    /// @return Vector containing only FFDHE groups.
    std::vector<crypto::GroupParams> getDhGroups() const
    {
        std::vector<crypto::GroupParams> dh;
        for (auto g : groups_)
        {
            if (g.isInFfdheRange())
            {
                dh.emplace_back(std::move(g));
            }
        }
        return dh;
    }

    /// @brief Serialize the extension to a byte buffer.
    ///
    /// @param[in] side The side of the connection (client/server).
    /// @param[in] output Buffer to write the serialized data to.
    ///
    /// @return size_t Number of bytes written to output buffer.
    size_t serialize(Side side, nonstd::span<uint8_t> output) const override
    {
        (void)side;

        const uint16_t bytesSize = static_cast<uint16_t>(groups_.size() * 2);
        size_t i = 0;

        output[i++] = casket::get_byte<0>(bytesSize);
        output[i++] = casket::get_byte<1>(bytesSize);

        for (const auto& group : groups_)
        {
            auto wireCode = group.wireCode();
            output[i++] = casket::get_byte<0>(wireCode);
            output[i++] = casket::get_byte<1>(wireCode);
        }

        return i;
    }

    /// @brief Construct a Supported Groups extension from a list of groups.
    ///
    /// @param[in] groups Vector of group parameters to include in the extension.
    ///
    explicit SupportedGroups(std::vector<crypto::GroupParams> groups)
        : groups_(std::move(groups))
    {
    }

    /// @brief Construct a Supported Groups extension from raw data.
    ///
    /// @param[in] side The side of the connection (client/server).
    /// @param[in] input Raw bytes containing the supported groups data.
    ///
    SupportedGroups(Side, nonstd::span<const uint8_t> input)
        : groups_(ParseListItems<crypto::GroupParams>(input, "SupportedGroups"))
    {
    }

    /// @brief Check if the extension is empty
    /// @return bool True if no groups are supported, false otherwise
    bool empty() const override
    {
        return groups_.empty();
    }

private:
    std::vector<crypto::GroupParams> groups_; ///< List of supported cryptographic groups
};

} // namespace snet::tls