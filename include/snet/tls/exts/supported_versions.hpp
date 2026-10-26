#pragma once

#include <cstdint>
#include <vector>

#include <casket/nonstd/span.hpp>

#include <snet/tls/exts/extension_code.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/version.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

namespace snet::tls
{

/// Supported Versions extension (RFC 8446 §4.2.1).
///
/// Asymmetric wire format:
///   * ClientHello: `<1-byte length> <uint16 BE version>*`, length = 2 * count;
///   * ServerHello: `<uint16 BE version>` -- the selected version, no length.
///
/// The extension is empty on the wire in neither direction when present;
/// `empty()` reports `true` only when no versions are stored.
class SupportedVersions final
{
public:
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::SupportedVersions;
    }

    /// @brief Checks whether the extension has an empty body.
    /// @retval true  No versions stored (extension is skipped).
    /// @retval false Otherwise.
    bool empty() const noexcept
    {
        return versions_.empty();
    }

    /// @brief Serializes the extension into @p output.
    /// @param[in] side   Side (Client or Server).
    ///                   On `Side::Server`, exactly one version must be stored.
    /// @param[in] output Destination buffer.
    /// @return Bytes written on success, kSerializationFailed if @p output
    ///         is too small or the server-side invariant (`size() == 1`) fails.
    std::size_t serialize(Side side, nonstd::span<uint8_t> output) const noexcept
    {
        if (side == Side::Server)
        {
            if (versions_.size() != 1)
                return kSerializationFailed;
            if (output.size_bytes() < 2)
                return kSerializationFailed;
            output[0] = versions_[0].majorVersion();
            output[1] = versions_[0].minorVersion();
            return 2;
        }

        const std::size_t n = versions_.size();
        if (n > 127)
            return kSerializationFailed; // 2*n must fit 1-byte length
        const std::size_t bytes = 2 * n;
        if (output.size_bytes() < 1 + bytes)
            return kSerializationFailed;

        output[0] = static_cast<std::uint8_t>(bytes);
        std::size_t i = 1;
        for (const auto& v : versions_)
        {
            output[i++] = v.majorVersion();
            output[i++] = v.minorVersion();
        }
        return i;
    }

    SupportedVersions() noexcept = default;

    /// @brief Constructs from a single protocol version (server side).
    /// @param[in] version The protocol version.
    explicit SupportedVersions(ProtocolVersion version) noexcept
    {
        // No allocation for one element: use a tiny inline reserve trick
        // is not portable; just push_back in try/catch-free way is not
        // possible for std::vector. Use a fixed default-constructed value
        // and let the caller check `empty()` in the unlikely OOM case.
        try
        {
            versions_.push_back(version);
        }
        catch (...)
        {
            // OOM: leave empty; deserialize path never takes this branch.
        }
    }

    /// @brief Constructs from a list of versions (client side).
    /// @param[in] versions Supported versions; order is preserved.
    explicit SupportedVersions(std::vector<ProtocolVersion> versions) noexcept
        : versions_(std::move(versions))
    {
    }

    /// @brief Parses the extension body from @p input.
    /// @param[in] side  Side (Client or Server); selects the wire format.
    /// @param[in] input Wire bytes of the extension_data field.
    /// @return DecodeError::None on success;
    ///         NotEnoughBytes / LengthOutOfRange / TrailingBytes on
    ///         malformed input.
    utils::DecodeError deserialize(Side side, nonstd::span<const uint8_t> input) noexcept
    {
        versions_.clear();

        utils::DataReader reader("supported_versions", input);

        if (side == Side::Server)
        {
            // ServerHello: exactly 2 bytes, no length prefix.
            if (input.size() != 2)
                return utils::DecodeError::LengthOutOfRange;
            const std::uint16_t raw = reader.get_uint16_t();
            if (!reader.ok())
                return reader.take_error();

            try
            {
                versions_.push_back(ProtocolVersion(raw));
            }
            catch (...)
            {
                return utils::DecodeError::AllocationFailed;
            }
            reader.assert_done();
            return reader.take_error();
        }

        // ClientHello: <1-byte length> <uint16>*; length = 2 * count, count in [1, 127].
        const std::uint8_t len = reader.get_byte();
        if (!reader.ok())
            return reader.take_error();
        if (len == 0 || (len & 1u) != 0)
            return utils::DecodeError::LengthOutOfRange;
        if (len != reader.remaining_bytes())
            return utils::DecodeError::LengthOutOfRange;

        const std::size_t count = len / 2;
        try
        {
            versions_.reserve(count);
        }
        catch (...)
        {
            return utils::DecodeError::AllocationFailed;
        }

        for (std::size_t i = 0; i < count; ++i)
        {
            const std::uint16_t raw = reader.get_uint16_t();
            if (!reader.ok())
                return reader.take_error();
            try
            {
                versions_.push_back(ProtocolVersion(raw));
            }
            catch (...)
            {
                versions_.clear();
                return utils::DecodeError::AllocationFailed;
            }
        }
        reader.assert_done();
        return reader.take_error();
    }

    /// @brief Checks whether @p version is in the list.
    /// @param[in] version Protocol version to look up.
    /// @retval true  Present in the list.
    /// @retval false Not present.
    bool supports(ProtocolVersion version) const noexcept
    {
        for (const auto& v : versions_)
        {
            if (v == version)
                return true;
        }
        return false;
    }

    /// @brief Gets the list of stored versions in wire order.
    /// @return View over the owned vector; empty means "not encoded".
    nonstd::span<const ProtocolVersion> versions() const noexcept
    {
        return {versions_.data(), versions_.size()};
    }

private:
    std::vector<ProtocolVersion> versions_; ///< Stored versions; server side holds exactly 1.
};

} // namespace snet::tls