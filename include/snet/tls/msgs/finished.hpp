
#pragma once
#include <cstdint>
#include <vector>
#include <casket/nonstd/span.hpp>
#include <snet/tls/version.hpp>

namespace snet::tls
{

class Finished final
{
public:
    Finished() = default;

    ~Finished() = default;

    void deserialize(const ProtocolVersion& version, nonstd::span<const uint8_t> input);

    size_t serialize(const ProtocolVersion& version, nonstd::span<uint8_t> output) const;

    const std::vector<uint8_t>& getVerifyData() const noexcept
    {
        return verifyData_;
    }

private:
    std::vector<uint8_t> verifyData_;
};

} // namespace snet::tls
