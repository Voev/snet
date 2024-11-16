#pragma once
#include <span>
#include <vector>
#include <string_view>

namespace snet::tls {

class HandshakeHash final {
public:
    HandshakeHash();

    ~HandshakeHash() noexcept;

    void update(std::span<const uint8_t> in);

    std::vector<uint8_t> final(std::string_view algorithm) const;

    const std::vector<uint8_t>& getContents() const;

    void reset();

private:
    std::vector<uint8_t> messages_;
};

} // namespace snet::tls