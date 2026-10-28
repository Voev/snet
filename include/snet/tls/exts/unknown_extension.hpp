#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

#include <casket/nonstd/span.hpp>

#include <snet/tls/exts/extension_code.hpp>
#include <snet/tls/types.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

namespace snet::tls
{

/// Fallback storage for extension codes that are not in `ExtensionVariant`.
///
/// Unlike known extensions, `UnknownExtension` has no compile-time
/// `staticType()`: the code comes from the wire and is stored in `code_`.
/// This is why it lives outside `std::variant` -- `extensionType(v)` for a
/// variant alternative must be `constexpr`, which is impossible for a
/// runtime code.
class UnknownExtension final
{
public:
    explicit UnknownExtension(ExtensionCode code) noexcept
        : code_(code)
    {
    }

    /// @brief Constructs from a code and raw body.
    /// @param[in] code  Extension code (any value not handled by the variant).
    /// @param[in] body  Raw extension_data bytes; moved into the object.
    explicit UnknownExtension(ExtensionCode code, std::vector<std::uint8_t> body) noexcept
        : code_(code)
        , value_(std::move(body))
    {
    }

    /// @brief Parses the extension body from @p input (opaque; just copies).
    /// @param[in] side  Side (Client or Server); unused.
    /// @param[in] input Wire bytes of the extension_data field.
    /// @return DecodeError::None on success; AllocationFailed on OOM.
    utils::DecodeError deserialize(Side side, nonstd::span<const uint8_t> input) noexcept
    {
        (void)side;

        value_.clear();

        if (input.empty())
        {
            return utils::DecodeError::None;
        }

        try
        {
            value_.assign(input.begin(), input.end());
        }
        catch (...)
        {
            value_.clear();
            return utils::DecodeError::AllocationFailed;
        }
        return utils::DecodeError::None;
    }

    /// @brief Gets the extension code (runtime value, not `constexpr`).
    ExtensionCode type() const noexcept
    {
        return code_;
    }

    /// @brief Sets the code; used by `Extensions::deserialize` before parsing.
    void setType(ExtensionCode code) noexcept
    {
        code_ = code;
    }

    /// @brief Checks whether the extension has an empty body.
    /// @retval false Always; unknown extensions are preserved verbatim.
    bool empty() const noexcept
    {
        return false;
    }

    /// @brief Serializes the extension into @p output.
    /// @param[in] side   Side (Client or Server); unused.
    /// @param[in] output Destination buffer; must hold value_.size() bytes.
    /// @return Bytes written on success, kSerializationFailed if @p output
    ///         is too small or the body exceeds 65535 bytes.
    std::size_t serialize(Side side, nonstd::span<uint8_t> output) const noexcept
    {
        (void)side;

        const std::size_t n = value_.size();
        if (n > 0xFFFF)
        {
            return 0;
        }

        if (output.size_bytes() < n)
        {
            return 0;
        }

        if (n)
        {
            std::memcpy(output.data(), value_.data(), n);
        }
        return n; // 0 is a valid wire form (empty unknown extension body)
    }

    /// @brief Gets the raw unknown body.
    /// @return View over the owned buffer.
    nonstd::span<const std::uint8_t> value() const noexcept
    {
        return {value_.data(), value_.size()};
    }

private:
    ExtensionCode code_;              ///< Runtime code.
    std::vector<std::uint8_t> value_; ///< Opaque body, verbatim.
};

} // namespace snet::tls