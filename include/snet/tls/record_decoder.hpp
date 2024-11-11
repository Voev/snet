#pragma once
#include <vector>
#include <span>
#include <snet/tls/types.hpp>
#include <snet/tls/cipher_suite.hpp>
#include <snet/tls/version.hpp>

namespace snet::tls
{

class RecordDecoder
{
public:
    RecordDecoder();

    ~RecordDecoder();

    RecordDecoder(CipherSuite cs, std::span<const uint8_t> mk,
                  const std::vector<uint8_t>& sk,
                  const std::vector<uint8_t>& iv);

    void initAEAD(CipherSuite cs, const std::vector<uint8_t>& encKey,
                  const std::vector<uint8_t>& encIV);

    void tls_decrypt(RecordType rt, ProtocolVersion version,
                     std::span<const uint8_t> in, std::vector<uint8_t>& out,
                     bool encryptThenMac);

    void tls13_decrypt(RecordType rt, std::span<const uint8_t> in,
                       std::vector<uint8_t>& out);

    void tls13_update_keys(const std::vector<uint8_t>& newkey,
                           const std::vector<uint8_t>& newiv);

private:
    void ssl3_check_mac(RecordType recordType, std::span<const uint8_t> content,
                        std::span<const uint8_t> mac);

    void tls_check_mac(RecordType recordType, ProtocolVersion version,
                       std::span<const uint8_t> iv,
                       std::span<const uint8_t> content,
                       std::span<const uint8_t> mac);

private:
    CipherSuite cipherSuite_;
    std::vector<uint8_t> macKey_;
    std::vector<uint8_t> implicitIv_; /* for AEAD ciphers */
    std::vector<uint8_t> writeKey_;   /* for AEAD ciphers */
    EvpCipherCtxPtr cipher_;
    uint64_t seq_;
};

} // namespace snet::tls
