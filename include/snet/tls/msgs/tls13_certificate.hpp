#pragma once
#include <cstdint>
#include <vector>
#include <casket/nonstd/span.hpp>
#include <casket/utils/noncopyable.hpp>
#include <snet/tls/extensions.hpp>

namespace snet::tls
{

struct TLSv13Certificate final : public casket::NonCopyable
{
    TLSv13Certificate() = default;

    ~TLSv13Certificate() = default;

    TLSv13Certificate(TLSv13Certificate&& other) noexcept = default;

    TLSv13Certificate& operator=(TLSv13Certificate&& other) noexcept = default;

    void deserialize(Side side, nonstd::span<const uint8_t> input);

    size_t serialize(Side side, nonstd::span<uint8_t> output) const;

    std::vector<uint8_t> requestContext;
    std::vector<std::vector<uint8_t>> certs;
    std::vector<Extensions> certExts;
};

} // namespace snet::tls