#pragma once
#include <span>
#include <variant>
#include <vector>

#include <snet/tls/record/not_inited_cipher.hpp>
#include <snet/tls/record/tls1_aead_cipher.hpp>
#include <snet/tls/record/tls1_block_cipher.hpp>
#include <snet/tls/record/tls1_stream_cipher.hpp>
#include <snet/tls/record/tls13_aead_cipher.hpp>

#include <snet/tls/cipher_suite_manager.hpp>
#include <snet/tls/version.hpp>

#include <snet/crypto/pointers.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::tls
{

class CipherContext final
{
public:
    CipherContext()
        : cipherType_(NotInitedCipher())
        , cipherContext_(EVP_CIPHER_CTX_new())
    {
        crypto::ThrowIfTrue(cipherContext_ == nullptr);
    }

    ~CipherContext() noexcept
    {
        cipherContext_.reset();
    }

    void reset() noexcept
    {
        cipherType_ = NotInitedCipher();
        EVP_CIPHER_CTX_reset(cipherContext_);
        macKey_.clear();
        implicitIV_.clear();
    }

    bool isInited() const
    {
        return !std::holds_alternative<NotInitedCipher>(cipherType_);
    }

    void setMacKey(std::span<const std::uint8_t> macKey)
    {
        std::visit(
            [&](auto&& arg)
            {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, v1::BlockCipher> || std::is_same_v<T, v1::StreamCipher>)
                {
                    macKey_.resize(macKey.size());
                    memcpy(macKey_.data(), macKey.data(), macKey.size());
                }
                else
                {
                    throw std::logic_error("not supported operation for cipher type");
                }
            },
            cipherType_);
    }

    inline void setCipherType(const CipherTraits& cipherTraits)
    {
        if (cipherTraits.aead)
        {
            if (cipherTraits.version == ProtocolVersion::TLSv1_3)
            {
                cipherType_ = v13::AeadCipher();
            }
            else
            {
                cipherType_ = v1::AeadCipher();
            }
        }
        else if (cipherTraits.blockSize == 1)
        {
            cipherType_ = v1::StreamCipher();
        }
        else
        {
            cipherType_ = v1::BlockCipher();
        }
    }

    void initDecrypt(const CipherTraits& cipherTraits, std::span<const uint8_t> encKey, std::span<const uint8_t> encIV)
    {
        setCipherType(cipherTraits);

        std::visit(
            [&](auto&& cipher)
            {
                using T = std::decay_t<decltype(cipher)>;
                if constexpr (std::is_same_v<T, v1::BlockCipher> || std::is_same_v<T, v1::StreamCipher>)
                {
                    //return cipher.initDecrypt(cipherContext_, cipherTraits, encKey, encIV);
                }
                else if constexpr (std::is_same_v<T, v1::AeadCipher> || std::is_same_v<T, v13::AeadCipher>)
                {
                    implicitIV_.resize(encIV.size());
                    memcpy(implicitIV_.data(), encIV.data(), encIV.size());

                    //return cipher.initDecrypt(cipherContext_, cipherTraits, encKey);
                }
            },
            cipherType_);
    }

    void decrypt(const CipherTraits& cipherTraits, uint64_t seq, RecordType rt, const uint8_t* inputBytes,
                 const size_t inputLength, uint8_t* outputBytes, size_t* outputLength)
    {
        std::visit(
            [&](auto&& cipher)
            {
                using T = std::decay_t<decltype(cipher)>;
                if constexpr (std::is_same_v<T, v1::BlockCipher> || std::is_same_v<T, v1::StreamCipher>)
                {
                    //return cipher.decrypt(cipherContext_, cipherTraits, seq, rt, in, out, macKey_);
                }
                if constexpr (std::is_same_v<T, v1::AeadCipher> || std::is_same_v<T, v13::AeadCipher>)
                {
                    //return cipher.decrypt(cipherContext_, cipherTraits, seq, rt, in, out, implicitIV_);
                }
            },
            cipherType_);
    }

private:
    std::variant<NotInitedCipher, v13::AeadCipher, v1::AeadCipher, v1::BlockCipher, v1::StreamCipher> cipherType_;
    crypto::CipherCtxPtr cipherContext_;
    std::vector<uint8_t> macKey_;
    std::vector<uint8_t> implicitIV_;
};
} // namespace snet::tls