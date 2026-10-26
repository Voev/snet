#pragma once

#include <array>
#include <cstdint>
#include <cstring>

#include <casket/nonstd/span.hpp>
#include <casket/nonstd/string_view.hpp>

#include <snet/tls/exts/extension_code.hpp>
#include <snet/tls/types.hpp>
#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

/// @brief Server Name Indication extension (RFC 6066, formerly RFC 3546).
///
/// Carries the `server_name` list:
///   * ClientHello: `ServerNameList` with one or more `ServerName` entries;
///     we parse the first `host_name` entry and ignore the rest.
///   * ServerHello: empty `extension_data` -- just an acknowledgement.
///
/// Storage is an inline 256-byte buffer; RFC 6066 limits `host_name` to 255
/// bytes, so no allocation is ever needed.
class ServerNameIndicator final
{
public:
    /// @brief Maximum hostname length, per RFC 6066.
    static constexpr std::size_t kMaxHostname = 255;

    /// @brief Gets the wire code for this extension.
    /// @return ExtensionCode::ServerNameIndication.
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::ServerNameIndication;
    }

    /// @brief Checks whether the extension has an empty body.
    /// @retval false Always; SNI is encoded even with an empty hostname
    ///         (that is the server-side acknowledgement form).
    bool empty() const noexcept
    {
        return false;
    }

    /// @brief Serializes the extension into @p output.
    /// @param[in] side   Side (Client or Server).
    ///                   On `Side::Server`, writes 0 bytes (empty ack).
    /// @param[in] output Destination buffer; must hold `5 + hostname size` bytes.
    /// @return Bytes written on success, `kSerializationFailed` if @p output
    ///         is too small or @p side is `Side::Server`.
    std::size_t serialize(Side side, nonstd::span<uint8_t> output) const noexcept
    {
        if (side == Side::Server)
            return kSerializationFailed;

        const std::uint16_t n = len_;
        if (output.size_bytes() < static_cast<uint16_t>(n + 5))
        {
            return kSerializationFailed;
        }

        const auto listLen = static_cast<std::uint16_t>(n + 3);
        output[0] = casket::get_byte<0>(listLen);
        output[1] = casket::get_byte<1>(listLen);
        output[2] = 0;
        output[3] = casket::get_byte<0>(n);
        output[4] = casket::get_byte<1>(n);
        if (n)
        {
            std::memcpy(output.data() + 5, buf_.data(), n);
        }
        return 5 + n;
    }

    /// @brief Default constructor; hostname is empty.
    ServerNameIndicator() noexcept = default;

    /// @brief Constructs from a hostname.
    /// @param[in] hostname Server name; must be <= 255 bytes.
    /// @note No validation is performed here (the ctor is `noexcept`).
    ///       If @p hostname is longer than 255 bytes it is truncated.
    explicit ServerNameIndicator(nonstd::string_view hostname) noexcept
    {
        len_ = static_cast<std::uint16_t>(std::min<std::size_t>(hostname.size(), kMaxHostname));
        if (len_)
        {
            std::memcpy(buf_.data(), hostname.data(), len_);
        }
    }

    /// @brief Parses the extension body from @p input.
    /// @param[in] side  Side (Client or Server); unused.
    /// @param[in] input Wire bytes of the extension_data field.
    /// @return DecodeError::None on success;
    ///         LengthOutOfRange / TrailingBytes on malformed input.
    ///         On failure the object is left with an empty hostname
    ///         (strong guarantee).
    utils::DecodeError deserialize(Side side, nonstd::span<const uint8_t> input) noexcept
    {
        (void)side;

        clear();

        if (input.empty())
        {
            return utils::DecodeError::None;
        }

        utils::DataReader reader("SNI", input);

        const std::uint16_t listLen = reader.get_uint16_t();
        if (!reader.ok())
        {
            return reader.take_error();
        }

        if (listLen != reader.remaining_bytes())
        {
            return utils::DecodeError::LengthOutOfRange;
        }

        bool gotHostName = false;
        while (reader.has_remaining())
        {
            const std::uint8_t nameType = reader.get_byte();
            if (!reader.ok())
            {
                return reader.take_error();
            }

            if (nameType == 0)
            {
                const auto hv = reader.get_string_view(2, 1, kMaxHostname);
                if (!reader.ok())
                {
                    return reader.take_error();
                }

                len_ = static_cast<std::uint16_t>(hv.size());
                std::memcpy(buf_.data(), hv.data(), len_);
                gotHostName = true;
                break;
            }

            const std::uint16_t skipLen = reader.get_uint16_t();
            if (!reader.ok())
            {
                return reader.take_error();
            }

            reader.discard_next(skipLen);
            if (!reader.ok())
            {
                return reader.take_error();
            }
        }

        reader.assert_done();
        if (!reader.ok())
        {
            return reader.take_error();
        }

        if (!gotHostName)
        {
            return utils::DecodeError::LengthOutOfRange;
        }

        return utils::DecodeError::None;
    }

    /// @brief Gets the hostname.
    /// @return View over the owned inline buffer; empty if none was parsed.
    nonstd::string_view getHostname() const noexcept
    {
        return {buf_.data(), len_};
    }

private:
    /// @brief Clears the stored hostname length (buffer is not zeroed).
    void clear() noexcept
    {
        len_ = 0;
    }

    std::array<char, kMaxHostname + 1> buf_{}; ///< Hostname bytes (no NUL needed).
    std::uint16_t len_{0};                     ///< Hostname length in bytes.
};

} // namespace snet::tls