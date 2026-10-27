#include <snet/tls/msgs/certificate_verify.hpp>

#include <algorithm>
#include <array>
#include <cstring>

#include <casket/utils/string.hpp>

#include <snet/crypto/crypto_manager.hpp>
#include <snet/crypto/signature.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>
#include <snet/utils/decode_error.hpp>

using namespace snet::crypto;
using namespace snet::utils;

namespace snet::tls
{

namespace
{

constexpr std::size_t kTls13TbsStartSize = 64;
constexpr std::size_t kTls13TbsLabelSize = 34;
constexpr std::size_t kMaxTbsSize = kTls13TbsStartSize + kTls13TbsLabelSize + EVP_MAX_MD_SIZE;

const std::array<std::uint8_t, kTls13TbsStartSize> kStartTbs = {
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20};

/// ASCII: "TLS 1.3, server CertificateVerify" with 0x00
const std::array<std::uint8_t, kTls13TbsLabelSize> kServerContext = {
    0x54, 0x4c, 0x53, 0x20, 0x31, 0x2e, 0x33, 0x2c, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x43,
    0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x00};

/// ASCII: "TLS 1.3, client CertificateVerify" with 0x00
const std::array<std::uint8_t, kTls13TbsLabelSize> kClientContext = {
    0x54, 0x4c, 0x53, 0x20, 0x31, 0x2e, 0x33, 0x2c, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x43,
    0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x00};

inline nonstd::span<std::uint8_t> constructSigningData(std::int8_t sideIndex,
                                                       nonstd::span<const std::uint8_t> transcriptHash,
                                                       nonstd::span<std::uint8_t> buffer) noexcept
{
    auto writePos = buffer.begin();
    writePos = std::copy(kStartTbs.begin(), kStartTbs.end(), writePos);

    if (sideIndex == 0)
    {
        writePos = std::copy(kClientContext.begin(), kClientContext.end(), writePos);
    }
    else
    {
        writePos = std::copy(kServerContext.begin(), kServerContext.end(), writePos);
    }

    writePos = std::copy(transcriptHash.begin(), transcriptHash.end(), writePos);
    return buffer.subspan(0, static_cast<std::size_t>(std::distance(buffer.begin(), writePos)));
}

inline std::error_code readScheme(utils::DataReader& reader, crypto::SignatureScheme& scheme) noexcept
{
    scheme = crypto::SignatureScheme(reader.get_uint16_t());
    return reader.take_ec();
}

} // namespace

std::error_code CertificateVerify::deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo) noexcept
{
    scheme = crypto::SignatureScheme(0);
    signature = {};

    utils::DataReader reader(input);

    if (metaInfo.version >= ProtocolVersion::TLSv1_2)
    {
        scheme = crypto::SignatureScheme(reader.get_uint16_t());
        if (!reader.ok())
            return reader.take_ec();
    }

    signature = reader.get_span_length_and_value(2);
    if (!reader.ok())
        return reader.take_ec();

    reader.assert_done();
    return reader.take_ec();
}

std::size_t CertificateVerify::serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept
{
    (void)session;

    if (output.size_bytes() < 2)
        return kSerializationFailed;

    const auto scheme16 = static_cast<std::uint16_t>(scheme.wireCode());
    output[0] = static_cast<std::uint8_t>(scheme16 >> 8);
    output[1] = static_cast<std::uint8_t>(scheme16);

    const std::size_t n = AppendLengthAndValue(output.subspan(2), signature.data(), signature.size(), 2);
    if (n == kSerializationFailed)
        return kSerializationFailed;

    return 2 + n;
}

nonstd::span<std::uint8_t> CertificateVerify::doTLSv13Sign(const crypto::SignatureScheme& scheme, std::int8_t sideIndex,
                                                           HashCtx* ctx, Key* privateKey,
                                                           nonstd::span<const std::uint8_t> transcriptHash,
                                                           nonstd::span<std::uint8_t> signatureBuffer)
{
    std::array<std::uint8_t, kMaxTbsSize> signingBuffer;
    HashAlg hash{nullptr};

    ThrowIfFalse(privateKey, "Invalid private key");

    auto hashName = scheme.getHashAlgorithm();
    if (!casket::equals(hashName, "UNDEF"))
    {
        hash = CryptoManager::getInstance().fetchDigest(hashName);
    }

    auto tbs = constructSigningData(sideIndex, transcriptHash, signingBuffer);
    return Signature::signMessage(ctx, scheme.getKeyAlgorithm(), hash, privateKey, signatureBuffer, tbs);
}

void CertificateVerify::doTLSv13Verify(const CertificateVerify& certVerify, std::int8_t sideIndex, HashCtx* ctx,
                                       Key* publicKey, nonstd::span<const std::uint8_t> transcriptHash)
{
    std::array<std::uint8_t, kMaxTbsSize> signingBuffer;
    HashAlg hash{nullptr};

    auto hashName = certVerify.scheme.getHashAlgorithm();
    if (!casket::equals(hashName, "UNDEF"))
    {
        hash = CryptoManager::getInstance().fetchDigest(hashName);
    }

    auto tbs = constructSigningData(sideIndex, transcriptHash, signingBuffer);
    Signature::verifyMessage(ctx, certVerify.scheme.getKeyAlgorithm(), hash, publicKey, certVerify.signature, tbs);
}

} // namespace snet::tls