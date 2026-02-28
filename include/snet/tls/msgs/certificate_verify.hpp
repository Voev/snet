#pragma once
#include <cstdint>
#include <casket/nonstd/span.hpp>

#include <snet/utils/algorithm.hpp>
#include <snet/crypto/signature_scheme.hpp>
#include <snet/tls/meta_info.hpp>

namespace snet::tls
{

class Session;

struct CertificateVerify final
{
    void parse(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    static CertificateVerify deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    size_t serialize(nonstd::span<uint8_t> output, const Session& session) const;

    static nonstd::span<uint8_t> doTLSv13Sign(const crypto::SignatureScheme& scheme, const int8_t sideIndex,
                                              HashCtx* ctx, Key* privateKey, nonstd::span<const uint8_t> transcriptHash,
                                              nonstd::span<uint8_t> signatureBuffer);

    static void doTLSv13Verify(const CertificateVerify& certVerify, const int8_t sideIndex, HashCtx* ctx,
                               Key* publicKey, nonstd::span<const uint8_t> transcriptHash);

    crypto::SignatureScheme scheme{0};
    nonstd::span<const uint8_t> signature;
};

inline crypto::SignatureScheme ChooseSignatureScheme(const Key* key,
                                                     nonstd::span<const crypto::SignatureScheme> allowedSchemes,
                                                     nonstd::span<const crypto::SignatureScheme> peerAllowedSchemes)
{
    for (auto scheme : allowedSchemes)
    {
        if (scheme.isSuitableFor(key) && ValueExists(peerAllowedSchemes, scheme))
        {
            return scheme;
        }
    }

    return crypto::SignatureScheme::NONE;
}

} // namespace snet::tls