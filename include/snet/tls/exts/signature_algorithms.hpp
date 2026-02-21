#pragma once
#include <vector>
#include <casket/utils/exception.hpp>
#include <snet/crypto/signature_scheme.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/exts/extension.hpp>
#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

inline std::vector<crypto::SignatureScheme> ParseSignatureAlgorithms(Side side, nonstd::span<const uint8_t> input,
                                                                     const char* name)
{
    (void)side;

    utils::DataReader reader(name, input);
    uint16_t len = reader.get_uint16_t();

    casket::ThrowIfTrue(/*len + 2 != reader.remaining_bytes() ||*/ len % 2 == 1 || len == 0,
                        "Bad encoding on signature algorithms extension");

    std::vector<crypto::SignatureScheme> schemes;
    schemes.reserve(len / 2);
    while (len)
    {
        schemes.emplace_back(reader.get_uint16_t());
        len -= 2;
    }

    return schemes;
}

/**
 * Signature Algorithms Extension for TLS 1.2 (RFC 5246)
 */
class SignatureAlgorithms final : public Extension
{
public:
    static ExtensionCode staticType()
    {
        return ExtensionCode::SignatureAlgorithms;
    }

    ExtensionCode type() const override
    {
        return staticType();
    }

    const std::vector<crypto::SignatureScheme>& supportedSchemes() const
    {
        return schemes_;
    }

    /// @brief Serialize extension to bytes.
    ///
    /// @param[in] side Side (Client or Server).
    /// @param[in] output Buffer for encoding.
    ///
    /// @return Serialized bytes count.
    size_t serialize(Side side, nonstd::span<uint8_t> output) const override
    {
        (void)side;

        const uint16_t bytesSize = static_cast<uint16_t>(schemes_.size() * 2);
        size_t i = 0;

        output[i++] = casket::get_byte<0>(bytesSize);
        output[i++] = casket::get_byte<1>(bytesSize);

        for (const auto& scheme : schemes_)
        {
            output[i++] = casket::get_byte<0>(scheme.wireCode());
            output[i++] = casket::get_byte<1>(scheme.wireCode());
        }

        return i;
    }

    bool empty() const override
    {
        return schemes_.empty();
    }

    SignatureAlgorithms(Side side, nonstd::span<const uint8_t> input)
        : schemes_(ParseSignatureAlgorithms(side, input, "SignatureAlgorithms"))
    {
    }

    explicit SignatureAlgorithms(std::vector<crypto::SignatureScheme> schemes)
        : schemes_(std::move(schemes))
    {
    }

private:
    std::vector<crypto::SignatureScheme> schemes_;
};

} // namespace snet::tls