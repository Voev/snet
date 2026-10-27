#pragma once

#include <cstdint>
#include <vector>

#include <casket/nonstd/span.hpp>
#include <casket/utils/load_store.hpp>

#include <snet/crypto/group_params.hpp>
#include <snet/tls/exts/extension_code.hpp>
#include <snet/tls/types.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

namespace snet::tls
{

/// Supported Groups Extension (RFC 7919, formerly "Supported Elliptic Curves").
///
/// Wire format: `<2-byte length> <uint16 BE group code>*`.
/// The length MUST be even and non-zero; groups are stored in wire order,
/// duplicates are preserved (RFC 7919 does not require de-duplication).
class SupportedGroups final
{
public:
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::SupportedGroups;
    }

    /// @brief Checks whether the extension has an empty body.
    /// @retval true  No groups (extension is skipped).
    /// @retval false Otherwise.
    bool empty() const noexcept
    {
        return groups_.empty();
    }

    /// @brief Serializes the extension into @p output.
    /// @param[in] side   Side (Client or Server); unused.
    /// @param[in] output Destination buffer; must hold 2 + 2 * groups_.size() bytes.
    /// @return Bytes written on success, kSerializationFailed if @p output
    ///         is too small or the list does not fit a 16-bit length.
    std::size_t serialize(Side side, nonstd::span<uint8_t> output) const noexcept
    {
        (void)side;

        const std::size_t bytesSize = groups_.size() * 2;
        if (bytesSize > 0xFFFF)
            return kSerializationFailed;
        if (output.size_bytes() < 2 + bytesSize)
            return kSerializationFailed;

        const auto bytesSize16 = static_cast<std::uint16_t>(bytesSize);
        output[0] = casket::get_byte<0>(bytesSize16);
        output[1] = casket::get_byte<1>(bytesSize16);

        std::size_t i = 2;
        for (const auto& group : groups_)
        {
            const auto wire = group.wireCode();
            output[i++] = casket::get_byte<0>(wire);
            output[i++] = casket::get_byte<1>(wire);
        }
        return i;
    }

    SupportedGroups() noexcept = default;

    /// @brief Constructs from an existing list of groups.
    /// @param[in] groups Supported groups; wire order is preserved.
    explicit SupportedGroups(std::vector<crypto::GroupParams> groups) noexcept
        : groups_(std::move(groups))
    {
    }

    /// @brief Parses the extension body from @p input.
    /// @param[in] side  Side (Client or Server); unused.
    /// @param[in] input Wire bytes of the extension_data field.
    /// @return DecodeError::None on success;
    ///         NotEnoughBytes / LengthOutOfRange / SizeNotMultiple /
    ///         TrailingBytes on malformed input.
    utils::DecodeError deserialize(Side side, nonstd::span<const uint8_t> input) noexcept
    {
        (void)side;

        groups_.clear();

        utils::DataReader reader(input);

        const std::uint16_t length = reader.get_uint16_t();
        if (!reader.ok())
        {
            return reader.take_error();
        }
        if (length == 0 || (length & 1u) != 0)
        {
            return utils::DecodeError::LengthOutOfRange;
        }

        if (length != reader.remaining_bytes())
        {
            return utils::DecodeError::LengthOutOfRange;
        }

        const std::size_t count = length / 2;
        try
        {
            groups_.reserve(count);
        }
        catch (...)
        {
            return utils::DecodeError::AllocationFailed;
        }

        for (std::size_t i = 0; i < count; ++i)
        {
            const std::uint16_t code = reader.get_uint16_t();
            if (!reader.ok())
            {
                return reader.take_error();
            }

            try
            {
                groups_.emplace_back(code);
            }
            catch (...)
            {
                groups_.clear();
                return utils::DecodeError::AllocationFailed;
            }
        }
        reader.assert_done();
        return reader.take_error();
    }

    /// @brief Gets all supported groups in wire order.
    /// @return View over the owned vector.
    nonstd::span<const crypto::GroupParams> groups() const noexcept
    {
        return {groups_.data(), groups_.size()};
    }

    /// @brief Collects the ECDH-curve groups into @p out.
    /// @param[out] out Output vector; cleared and filled with ECDH groups.
    void getEcGroups(std::vector<crypto::GroupParams>& out) const
    {
        out.clear();
        for (const auto& g : groups_)
        {
            if (g.isPureEccGroup())
            {
                out.push_back(g);
            }
        }
    }

    /// @brief Collects the FFDHE-range groups into @p out.
    /// @param[out] out Output vector; cleared and filled with FFDHE groups.
    void getDhGroups(std::vector<crypto::GroupParams>& out) const
    {
        out.clear();
        for (const auto& g : groups_)
        {
            if (g.isInFfdheRange())
            {
                out.push_back(g);
            }
        }
    }

private:
    std::vector<crypto::GroupParams> groups_; ///< Supported groups, wire order preserved.
};

} // namespace snet::tls