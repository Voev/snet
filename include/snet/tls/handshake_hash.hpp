#pragma once
#include <algorithm>
#include <span>
#include <vector>
#include <snet/tls/types.hpp>
#include <snet/tls/cipher_suite.hpp>
#include <snet/tls/exception.hpp>

namespace snet::tls {

class HandshakeHash final {
public:
    HandshakeHash() = default;

    void update(std::span<const uint8_t> in) {
        std::copy(in.begin(), in.end(), std::back_inserter(m_data));
    }

    std::vector<uint8_t> final(MACAlg mac_algo) const {
        const EVP_MD* md = GetMacAlgorithm(mac_algo);
        tls::ThrowIfFalse(md != nullptr);

        EvpMdCtxPtr ctx(EVP_MD_CTX_new());
        tls::ThrowIfFalse(ctx != nullptr);

        tls::ThrowIfFalse(0 < EVP_DigestInit(ctx, md));
        tls::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, m_data.data(), m_data.size()));

        unsigned int outlen(EVP_MD_size(md));
        std::vector<uint8_t> out(outlen);
        tls::ThrowIfFalse(0 < EVP_DigestFinal(ctx, out.data(), &outlen));
        out.resize(outlen);

        return out;
    }

    const std::vector<uint8_t>& get_contents() const {
        return m_data;
    }

    void reset() {
        m_data.clear();
    }

private:
    std::vector<uint8_t> m_data;
};

} // namespace snet::tls