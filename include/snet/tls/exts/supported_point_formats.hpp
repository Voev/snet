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

class SupportedPointFormats final : public Extension
{
public:
    static ExtensionCode staticType();

    ExtensionCode type() const override;

    bool empty() const override;

    size_t serialize(Side side, std::span<uint8_t> output) const override;

    SupportedPointFormats(Side side, std::span<const uint8_t> input);

    SupportedPointFormats(const std::vector<ECPointFormat>& formats);

    const std::vector<ECPointFormat>& getFormats() const;

private:
    std::vector<ECPointFormat> formats_;
};

} // namespace snet::tls