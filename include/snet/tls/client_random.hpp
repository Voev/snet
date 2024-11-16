#pragma once
#include <vector>
#include <cstdint>

namespace snet::tls {

using ClientRandom = std::vector<uint8_t>;
using ServerRandom = std::vector<uint8_t>;

} // namespace snet::tls

namespace std {

template <>
struct hash<snet::tls::ClientRandom> {
    std::size_t operator()(const snet::tls::ClientRandom& random) const noexcept {
        std::size_t hash{0};
        for (auto byte : random) {
            hash = (hash << 5) - hash + byte;
        }
        return hash;
    }
};

} // namespace std