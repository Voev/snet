#pragma once

#include <cstdint>
#include <vector>

#include <casket/nonstd/span.hpp>

#include <snet/tls/exts/extension_code.hpp>
#include <snet/tls/types.hpp>
#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

/// PSK Key Exchange Modes (RFC 8446 §4.2.9).
///
/// Wire format: `<1-byte length> <mode byte>*`.
/// Known modes: 0 = psk_ke, 1 = psk_dhe_ke. Unknown modes are rejected.
enum class PskKeyExchangeMode : std::uint8_t
{
    PskKe = 0,    ///< PSK-only key establishment.
    PskDheKe = 1, ///< PSK with (EC)DHE key establishment.
};

constexpr bool isValidPskKeyExchangeMode(PskKeyExchangeMode m) noexcept
{
    switch (m)
    {
    case PskKeyExchangeMode::PskKe:
    case PskKeyExchangeMode::PskDheKe:
        return true;
    }
    return false;
}

class PskKeyExchangeModes final
{
public:
    static constexpr ExtensionCode staticType() noexcept
    {
        return ExtensionCode::PskKeyExchangeModes;
    }

    bool empty() const noexcept
    {
        return modes_.empty();
    }

    std::size_t serialize(Side /*side*/, nonstd::span<uint8_t> output) const noexcept
    {
        const std::size_t n = modes_.size();
        if (n == 0 || n > 255)
            return kSerializationFailed;
        if (output.size_bytes() < 1 + n)
            return kSerializationFailed;
        output[0] = static_cast<std::uint8_t>(n);
        for (std::size_t i = 0; i < n; ++i)
            output[1 + i] = static_cast<std::uint8_t>(modes_[i]);
        return 1 + n;
    }

    PskKeyExchangeModes() noexcept = default;

    explicit PskKeyExchangeModes(std::vector<PskKeyExchangeMode> modes) noexcept
        : modes_(std::move(modes))
    {
    }

    utils::DecodeError deserialize(Side /*side*/, nonstd::span<const uint8_t> input) noexcept
    {
        modes_.clear();

        utils::DataReader reader("PskKeyExchangeModes", input);
        const std::uint8_t len = reader.get_byte();
        if (!reader.ok())
            return reader.take_error();
        if (len == 0 || len != reader.remaining_bytes())
            return utils::DecodeError::LengthOutOfRange;

        try
        {
            modes_.reserve(len);
        }
        catch (...)
        {
            return utils::DecodeError::AllocationFailed;
        }

        for (std::size_t i = 0; i < len; ++i)
        {
            const auto raw = static_cast<PskKeyExchangeMode>(reader.get_byte());
            if (!reader.ok())
            {
                modes_.clear();
                return reader.take_error();
            }
            if (!isValidPskKeyExchangeMode(raw))
            {
                modes_.clear();
                return utils::DecodeError::LengthOutOfRange;
            }
            try
            {
                modes_.push_back(raw);
            }
            catch (...)
            {
                modes_.clear();
                return utils::DecodeError::AllocationFailed;
            }
        }
        reader.assert_done();
        return reader.take_error();
    }

    nonstd::span<const PskKeyExchangeMode> modes() const noexcept
    {
        return {modes_.data(), modes_.size()};
    }

private:
    std::vector<PskKeyExchangeMode> modes_;
};

} // namespace snet::tls