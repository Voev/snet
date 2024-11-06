#pragma once
#include <vector>
#include <span>
#include <snet/tls/types.hpp>
#include <snet/tls/cipher_suite.hpp>

namespace snet::tls {

class RecordDecoder {
public:
    RecordDecoder(
        CipherSuite cs, std::span<const uint8_t> mk, const std::vector<uint8_t>& sk, const std::vector<uint8_t>& iv);
    ~RecordDecoder();

    void tls_decrypt(RecordType rt, int version, std::span<const uint8_t> in, std::vector<uint8_t>& out);

    void tls13_decrypt(RecordType rt, std::span<const uint8_t> in, std::vector<uint8_t>& out);

    void tls13_update_keys(const std::vector<uint8_t>& newkey, const std::vector<uint8_t>& newiv);

private:
    void ssl3_check_mac(RecordType rt, int ver, uint8_t* data, uint32_t datalen, uint8_t* mac);

    void
    tls_check_mac(RecordType rt, int ver, uint8_t* data, uint32_t datalen, uint8_t* iv, uint32_t ivlen, uint8_t* mac);

private:
    CipherSuite cipherSuite_;
    std::vector<uint8_t> macKey_;
    std::vector<uint8_t> implicitIv_; /* for AEAD ciphers */
    std::vector<uint8_t> writeKey_;   /* for AEAD ciphers */
    EvpCipherCtxPtr cipher_;
    uint64_t seq_;
};

} // namespace snet::tls
