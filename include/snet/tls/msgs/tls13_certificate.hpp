#pragma once
#include <cstdint>
#include <vector>
#include <snet/cpp_port/span.hpp>
#include <snet/tls/extensions.hpp>
#include <snet/utils/noncopyable.hpp>

namespace snet::tls
{

struct TLSv13Certificate final : public utils::NonCopyable
{
    TLSv13Certificate() = default;

    ~TLSv13Certificate() = default;

    TLSv13Certificate(TLSv13Certificate&& other) noexcept = default;

    TLSv13Certificate& operator=(TLSv13Certificate&& other) noexcept = default;

    void deserialize(Side side, cpp::span<const uint8_t> input);

    size_t serialize(Side side, cpp::span<uint8_t> output) const;

    std::vector<uint8_t> requestContext;
    std::vector<std::vector<uint8_t>> certs;
    std::vector<Extensions> certExts;
};

} // namespace snet::tls