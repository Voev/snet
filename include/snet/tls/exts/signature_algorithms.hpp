#pragma once

#include <cstdint>
#include <vector>

#include <casket/nonstd/span.hpp>

#include <snet/crypto/signature_scheme.hpp>
#include <snet/tls/exts/extension_code.hpp>
#include <snet/tls/types.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

namespace snet::tls
{

/// Signature Algorithms Extension (RFC 5246 §7.4.1.4.1 for TLS 1.2,
/// RFC 8446 §4.2.3 for TLS 1.3).
///
/// Wire format: `<2-byte length> <uint16 BE signature scheme>*`.
/// The length MUST be even and non-zero; an empty list is invalid on the wire.
class SignatureAlgorithms final
{
public:
    /// @brief Gets the wire code for this extension.
    /// @return ExtensionCode::SignatureAlgorithms.
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::SignatureAlgorithms;
    }

    /// @brief Checks whether the extension has an empty body.
    /// @retval true  The scheme list is empty (extension is skipped).
    /// @retval false Otherwise.
    bool empty() const noexcept
    {
        return schemes_.empty();
    }

    /// @brief Serializes the extension into @p output.
    /// @param[in] side   Side (Client or Server); unused.
    /// @param[in] output Destination buffer; must hold 2 + 2 * schemes_.size() bytes.
    /// @return Bytes written on success, kSerializationFailed if @p output
    ///         is too small or the list is too long for a 16-bit length field.
    std::size_t serialize(Side side, nonstd::span<uint8_t> output) const noexcept
    {
        (void)side;

        const std::size_t bytesSize = schemes_.size() * 2;
        if (bytesSize > 0xFFFF)
        {
            return kSerializationFailed;
        }

        if (output.size_bytes() < 2 + bytesSize)
        {
            return kSerializationFailed;
        }

        const auto bytesSize16 = static_cast<std::uint16_t>(bytesSize);
        output[0] = casket::get_byte<0>(bytesSize16);
        output[1] = casket::get_byte<1>(bytesSize16);

        for (std::size_t i = 0; i < schemes_.size(); ++i)
        {
            const auto code = static_cast<std::uint16_t>(schemes_[i].wireCode());
            output[2 + 2 * i] = casket::get_byte<0>(code);
            output[2 + 2 * i + 1] = casket::get_byte<1>(code);
        }
        return 2 + bytesSize;
    }

    /// @brief Default constructor.
    SignatureAlgorithms() noexcept = default;

    /// @brief Constructs from an existing list of schemes.
    /// @param[in] schemes Supported signature schemes; order is preserved.
    explicit SignatureAlgorithms(std::vector<crypto::SignatureScheme> schemes) noexcept
        : schemes_(std::move(schemes))
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

        schemes_.clear();

        utils::DataReader reader("SignatureAlgorithms", input);

        // <2-byte length> <uint16>*; length must be even and non-zero.
        const std::uint16_t len = reader.get_uint16_t();
        if (!reader.ok())
        {
            return reader.take_error();
        }
        if (len == 0 || (len & 1u) != 0)
        {
            return utils::DecodeError::LengthOutOfRange;
        }
        if (len != reader.remaining_bytes())
        {
            return utils::DecodeError::LengthOutOfRange;
        }

        const std::size_t count = len / 2;
        try
        {
            schemes_.reserve(count);
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
                schemes_.emplace_back(code);
            }
            catch (...)
            {
                schemes_.clear();
                return utils::DecodeError::AllocationFailed;
            }
        }
        reader.assert_done();
        return reader.take_error();
    }

    /// @brief Gets the list of supported signature schemes.
    /// @return View over the owned vector; empty means "not encoded".
    nonstd::span<const crypto::SignatureScheme> supportedSchemes() const noexcept
    {
        return {schemes_.data(), schemes_.size()};
    }

private:
    std::vector<crypto::SignatureScheme> schemes_; ///< Supported schemes, wire order preserved.
};

} // namespace snet::tls