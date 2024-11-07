#include <snet/log/log_manager.hpp>

#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <snet/utils/endianness.hpp>
#include <snet/utils/exception.hpp>
#include <snet/utils/hexlify.hpp>
#include <snet/utils/load_store.hpp>

#include <snet/tls/exception.hpp>
#include <snet/tls/record_decoder.hpp>

#define MSB(a) ((a >> 8) & 0xff)
#define LSB(a) (a & 0xff)

namespace snet::tls
{

static int fmt_seq(uint32_t num, uint8_t* buf);

RecordDecoder::RecordDecoder(CipherSuite cs, std::span<const uint8_t> macKey,
                             const std::vector<uint8_t>& encKey,
                             const std::vector<uint8_t>& iv)
    : cipherSuite_(cs)
    , cipher_(EVP_CIPHER_CTX_new())
    , seq_(0)
{

    auto cipher = GetEncAlgorithm(cipherSuite_.getEncAlg());

    implicitIv_.resize(iv.size());
    memcpy(implicitIv_.data(), iv.data(), iv.size());

    writeKey_.resize(encKey.size());
    memcpy(writeKey_.data(), encKey.data(), encKey.size());

    if (cipherSuite_.isAEAD())
    {
        tls::ThrowIfFalse(0 <
                          EVP_CipherInit(cipher_, cipher, nullptr, nullptr, 0));
    }
    else
    {
        macKey_.resize(macKey.size());
        memcpy(macKey_.data(), macKey.data(), macKey.size());
        tls::ThrowIfFalse(
            0 < EVP_CipherInit(cipher_, cipher, encKey.data(), iv.data(), 0));
    }
}

RecordDecoder::~RecordDecoder() noexcept
{
}

void RecordDecoder::tls13_update_keys(const std::vector<uint8_t>& newkey,
                                      const std::vector<uint8_t>& newiv)
{
    std::copy(newkey.begin(), newkey.end(), writeKey_.begin());
    std::copy(newiv.begin(), newiv.end(), implicitIv_.begin());
    seq_ = 0;
}

void RecordDecoder::tls13_decrypt(RecordType rt, std::span<const uint8_t> in,
                                  std::vector<uint8_t>& out)
{
    int i;
    int x;
    std::array<uint8_t, 5> aad;
    std::array<uint8_t, 12> aead_nonce;
    int taglen = cipherSuite_.getEncAlg() == EncAlg::AES_128_CCM_8 ? 8 : 16;

    utils::printHex("CipherText", in);
    utils::printHex("KEY", writeKey_);
    utils::printHex("IV", implicitIv_);

    utils::ThrowIfFalse(cipherSuite_.isAEAD(), "it must be AEAD!");

    memcpy(aead_nonce.data(), implicitIv_.data(), 12);
    for (i = 0; i < 8; i++)
    { // AEAD NONCE according to RFC TLS1.3
        aead_nonce[12 - 1 - i] ^= ((seq_ >> (i * 8)) & 0xFF);
    }
    seq_++;

    auto data = in.subspan(0, in.size() - taglen);
    auto tag = in.subspan(in.size() - taglen, taglen);

    aad[0] = static_cast<uint8_t>(rt);
    aad[1] = 0x03;
    aad[2] = 0x03;
    uint16_t size = static_cast<uint16_t>(in.size());
    aad[3] = utils::get_byte<0>(size);
    aad[4] = utils::get_byte<1>(size);

    utils::printHex("NONCE", aead_nonce);
    utils::printHex("Tag", tag);
    utils::printHex("AAD", aad);

    tls::ThrowIfFalse(
        0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr));

    if (EVP_CIPHER_CTX_get_mode(cipher_) == EVP_CIPH_CCM_MODE)
    {
        tls::ThrowIfFalse(
            0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_TAG, tag.size(),
                                    const_cast<uint8_t*>(tag.data())));
    }

    tls::ThrowIfFalse(0 < EVP_DecryptInit_ex(cipher_, nullptr, nullptr,
                                             writeKey_.data(),
                                             aead_nonce.data()));

    int outSize{0};

    if (EVP_CIPHER_CTX_get_mode(cipher_) == EVP_CIPH_CCM_MODE)
    {
        tls::ThrowIfFalse(0 < EVP_DecryptUpdate(cipher_, nullptr, &outSize,
                                                nullptr, in.size()));
    }

    tls::ThrowIfFalse(0 < EVP_DecryptUpdate(cipher_, nullptr, &outSize,
                                            aad.data(), aad.size()));

    outSize = data.size();
    out.resize(outSize);
    tls::ThrowIfFalse(0 < EVP_DecryptUpdate(cipher_, out.data(), &outSize,
                                            data.data(), data.size()));
    out.resize(outSize);

    if (EVP_CIPHER_CTX_get_mode(cipher_) == EVP_CIPH_GCM_MODE)
    {
        tls::ThrowIfFalse(
            0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_GCM_SET_TAG, tag.size(),
                                    const_cast<uint8_t*>(tag.data())));
    }

    tls::ThrowIfFalse(0 < EVP_DecryptFinal(cipher_, nullptr, &x));
}

void RecordDecoder::tls_decrypt(RecordType rt, ProtocolVersion version,
                                std::span<const uint8_t> in,
                                std::vector<uint8_t>& out)
{
    uint8_t aead_tag[13], aead_nonce[12];

    if (cipherSuite_.isAEAD())
    {
        memcpy(aead_nonce, implicitIv_.data(), implicitIv_.size());
        memcpy(aead_nonce + implicitIv_.size(), in.data(), 12 - implicitIv_.size());
        in = in.subspan(12 - implicitIv_.size());

        tls::ThrowIfFalse(0 < EVP_DecryptInit(cipher_, nullptr,
                                              writeKey_.data(), aead_nonce));

        /*
           Then tag is always 16 bytes, as per:
           https://tools.ietf.org/html/rfc5116#section-5.2
        */
        auto data = in.subspan(0, in.size() - 16);
        auto tag = in.subspan(in.size() - 16, 16);

        tls::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t*>(tag.data())));

        fmt_seq(seq_, aead_tag);
        seq_++;
        aead_tag[8] = static_cast<uint8_t>(rt);
        aead_tag[9] = version.major_version();
        aead_tag[10] = version.minor_version();
        uint16_t size = static_cast<uint16_t>(in.size());
        aead_tag[11] = utils::get_byte<0>(size);
        aead_tag[12] = utils::get_byte<1>(size);

        int outSize{0};
        tls::ThrowIfFalse(0 < EVP_DecryptUpdate(cipher_, nullptr, &outSize, aead_tag, 13));

        outSize = out.size();
        out.resize(outSize);

        tls::ThrowIfFalse(0 < EVP_DecryptUpdate(cipher_, out.data(), &outSize, data.data(), data.size()));
        out.resize(outSize);

        int x{0};
        tls::ThrowIfFalse(0 < EVP_DecryptFinal(cipher_, nullptr, &x));
    }
    /*
       Encrypt-then-MAC is not used with AEAD ciphers, as per:
       https://tools.ietf.org/html/rfc7366#section-3
    */
    else if (false /* encrypt_then_mac == 2 */)
    {
        //*outl = inl;

        /* First strip off the MAC */
        //*outl -= macKey_.size();
        // mac = in + (*outl);

        // encpadl = *outl;
        /* Now decrypt */
        // EVP_Cipher(cipher_, out, in, *outl);

        /* And then strip off the padding*/
        if (EVP_CIPHER_CTX_get_block_size(cipher_) > 1)
        {
            // pad = out[*outl - 1];
            //*outl -= (pad + 1);
        }
        /* TLS 1.1 and beyond: remove explicit IV, only used with
         * non-stream ciphers. */
        /*if (d->version >= tls::ProtocolVersion::TLSv1_1 &&
        EVP_CIPHER_CTX_get_block_size(cipher_) > 1) { uint32_t blk =
        EVP_CIPHER_CTX_get_block_size(cipher_); if (blk <= *outl) { *outl -=
        blk; memmove(out, out + blk, *outl); } else { utils::ThrowIfTrue(true,
        "Block size greater than Plaintext!");
            }

            tls_check_mac(rt, version, in + blk, encpadl, in, blk, mac);

        } else {
            tls_check_mac(rt, version, in, encpadl, nullptr, 0, mac);
        }*/
    }
    else
    {
        /* First decrypt*/

        /*tls::ThrowIfFalse(0 < EVP_Cipher(cipher_, out, in, inl));

        *outl = inl;

        if (EVP_CIPHER_CTX_get_block_size(cipher_) > 1) {
            pad = out[inl - 1];
            *outl -= (pad + 1);
        }*/

        /* And the MAC */
        /**outl -= macKey_.size();
        mac = out + (*outl);

        if (d->version == ProtocolVersion::SSLv3_0) {
            ssl3_check_mac(rt, version, out, *outl, mac);
        } else {
            if (d->version >= ProtocolVersion::TLSv1_1 &&
        EVP_CIPHER_CTX_get_block_size(cipher_) > 1) { uint32_t blk =
        EVP_CIPHER_CTX_get_block_size(cipher_); if (blk <= *outl) { *outl -=
        blk; memmove(out, out + blk, *outl); } else { utils::ThrowIfTrue(true,
        "Block size greater than Plaintext!");
                }
            }
            tls_check_mac(rt, version, out, *outl, nullptr, 0, mac);
        }*/
    }
}

/* This should go to 2^128, but we're never really going to see
   more than 2^64, so we cheat*/
static int fmt_seq(uint32_t num, uint8_t* buf)
{
    uint32_t netnum;

    memset(buf, 0, 8);
    netnum = utils::host_to_be(num);
    memcpy(buf + 4, &netnum, 4);

    return 0;
}

void RecordDecoder::tls_check_mac(RecordType rt, int ver, uint8_t* data,
                                  uint32_t datalen, uint8_t* iv, uint32_t ivlen,
                                  uint8_t* mac)
{

    const EVP_MD* md;
    uint32_t l;
    uint8_t buf[128];

    HmacCtxPtr hm(HMAC_CTX_new());
    tls::ThrowIfFalse(hm != nullptr);

    md = GetMacAlgorithm(cipherSuite_.getHashAlg());
    ThrowIfFalse(md != nullptr);

    ThrowIfFalse(0 <
                 HMAC_Init_ex(hm, macKey_.data(), macKey_.size(), md, nullptr));

    fmt_seq(seq_, buf);
    seq_++;
    tls::ThrowIfFalse(0 < HMAC_Update(hm, buf, 8));
    buf[0] = static_cast<uint8_t>(rt);
    tls::ThrowIfFalse(0 < HMAC_Update(hm, buf, 1));

    buf[0] = utils::get_byte<0>(ver);
    buf[1] = utils::get_byte<1>(ver);
    tls::ThrowIfFalse(0 < HMAC_Update(hm, buf, 2));

    buf[0] = utils::get_byte<0>(datalen);
    buf[1] = utils::get_byte<1>(datalen);
    tls::ThrowIfFalse(0 < HMAC_Update(hm, buf, 2));

    /* for encrypt-then-mac with an explicit IV */
    if (ivlen && iv)
    {
        tls::ThrowIfFalse(0 < HMAC_Update(hm, iv, ivlen));
        tls::ThrowIfFalse(0 < HMAC_Update(hm, data, datalen - ivlen));
    }
    else
        tls::ThrowIfFalse(0 < HMAC_Update(hm, data, datalen));

    tls::ThrowIfFalse(0 < HMAC_Final(hm, buf, &l));
    utils::ThrowIfFalse(0 == memcmp(mac, buf, l), "Bad MAC");
}

void RecordDecoder::ssl3_check_mac(RecordType rt, int ver, uint8_t* data,
                                   uint32_t datalen, uint8_t* mac)
{

    (void)ver;
    const EVP_MD* md;
    uint32_t l;
    uint8_t buf[64], dgst[20];
    int pad_ct = (cipherSuite_.getHashAlg() == MACAlg::SHA1) ? 40 : 48;

    EvpMdCtxPtr mc(EVP_MD_CTX_new());
    tls::ThrowIfFalse(mc != nullptr);

    md = GetMacAlgorithm(cipherSuite_.getHashAlg());
    tls::ThrowIfFalse(md != nullptr);
    tls::ThrowIfFalse(0 < EVP_DigestInit(mc, md));
    tls::ThrowIfFalse(0 < EVP_DigestUpdate(mc, macKey_.data(), macKey_.size()));

    memset(buf, 0x36, pad_ct);
    tls::ThrowIfFalse(0 < EVP_DigestUpdate(mc, buf, pad_ct));

    fmt_seq(seq_, buf);
    seq_++;
    tls::ThrowIfFalse(0 < EVP_DigestUpdate(mc, buf, 8));

    buf[0] = static_cast<uint8_t>(rt);
    tls::ThrowIfFalse(0 < EVP_DigestUpdate(mc, buf, 1));

    buf[0] = utils::get_byte<0>(datalen);
    buf[1] = utils::get_byte<1>(datalen);
    tls::ThrowIfFalse(0 < EVP_DigestUpdate(mc, buf, 2));
    tls::ThrowIfFalse(0 < EVP_DigestUpdate(mc, data, datalen));
    tls::ThrowIfFalse(0 < EVP_DigestFinal(mc, dgst, &l));

    tls::ThrowIfFalse(0 < EVP_DigestInit(mc, md));
    tls::ThrowIfFalse(0 < EVP_DigestUpdate(mc, macKey_.data(), macKey_.size()));

    memset(buf, 0x5c, pad_ct);
    tls::ThrowIfFalse(0 < EVP_DigestUpdate(mc, buf, pad_ct));
    tls::ThrowIfFalse(0 < EVP_DigestUpdate(mc, dgst, l));
    tls::ThrowIfFalse(0 < EVP_DigestFinal(mc, dgst, &l));
    utils::ThrowIfFalse(0 == memcmp(mac, dgst, l), "Bad MAC");
}

} // namespace snet::tls