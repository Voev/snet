#include <limits>

#include <casket/utils/string.hpp>

#include <snet/tls/types.hpp>
#include <snet/tls/msgs/certificate_verify.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

#include <snet/crypto/signature.hpp>
#include <snet/crypto/crypto_manager.hpp>

using namespace snet::crypto;

namespace
{

static constexpr size_t TLS13_TBS_START_SIZE = 64;

static constexpr size_t TLS13_TBS_LABEL_SIZE = 34;

static constexpr size_t MAX_TBS_SIZE = TLS13_TBS_START_SIZE + TLS13_TBS_LABEL_SIZE + EVP_MAX_MD_SIZE;

/// To be signed message prefix for TLSv1.3
static const std::array<uint8_t, TLS13_TBS_START_SIZE> startTbs = {
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20};

/// ASCII: "TLS 1.3, server CertificateVerify" with 0x00
static const std::array<uint8_t, TLS13_TBS_LABEL_SIZE> serverContext = {
    0x54, 0x4c, 0x53, 0x20, 0x31, 0x2e, 0x33, 0x2c, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x43,
    0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x00};

/// ASCII: "TLS 1.3, client CertificateVerify" with 0x00
static const std::array<uint8_t, TLS13_TBS_LABEL_SIZE> clientContext = {
    0x54, 0x4c, 0x53, 0x20, 0x31, 0x2e, 0x33, 0x2c, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x43,
    0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x00};

inline nonstd::span<uint8_t> ConstructSigningData(const int8_t sideIndex, nonstd::span<const uint8_t> transcriptHash,
                                                  nonstd::span<uint8_t> buffer) noexcept
{
    auto writePos = buffer.begin();
    writePos = std::copy(std::begin(startTbs), std::end(startTbs), writePos);

    if (sideIndex == 0)
    {
        writePos = std::copy(std::begin(clientContext), std::end(clientContext), writePos);
    }
    else
    {
        writePos = std::copy(std::begin(serverContext), std::end(serverContext), writePos);
    }

    writePos = std::copy(transcriptHash.begin(), transcriptHash.end(), writePos);
    return buffer.subspan(0, std::distance(buffer.begin(), writePos));
}

} // namespace

namespace snet::tls
{

void CertificateVerify::parse(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo)
{
    utils::DataReader reader("CertificateVerify", input);

    if (metaInfo.version >= ProtocolVersion::TLSv1_2)
    {
        scheme = SignatureScheme(reader.get_uint16_t());
        signature = reader.get_span(2, 0, 65535);
    }
    else
    {
        signature = reader.get_span(2, 0, 65535);
    }

    reader.assert_done();
}

CertificateVerify CertificateVerify::deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo)
{
    CertificateVerify certVerify;
    certVerify.parse(input, metaInfo);
    return certVerify;
}

size_t CertificateVerify::serialize(nonstd::span<uint8_t> output, const Session& session) const
{
    (void)session;

    size_t length{};

    ThrowIfTrue(signature.size() > std::numeric_limits<uint16_t>::max(),
                "CertificateVerify signature too long to encode");

    const auto code = scheme.wireCode();
    output[0] = casket::get_byte<0>(code);
    output[1] = casket::get_byte<1>(code);
    length += 2;

    length += append_length_and_value(output.subspan(length), signature.data(), signature.size(), 2);
    return length;
}

nonstd::span<uint8_t> CertificateVerify::doTLSv13Sign(const SignatureScheme& scheme, const int8_t sideIndex,
                                                      HashCtx* ctx, Key* privateKey,
                                                      nonstd::span<const uint8_t> transcriptHash,
                                                      nonstd::span<uint8_t> signatureBuffer)
{
    std::array<uint8_t, MAX_TBS_SIZE> signingBuffer;
    HashAlg hash{nullptr};

    ThrowIfFalse(privateKey, "Invalid private key");

    auto hashName = scheme.getHashAlgorithm();
    if (!casket::equals(hashName, "UNDEF"))
    {
        hash = CryptoManager::getInstance().fetchDigest(hashName);
    }

    auto tbs = ::ConstructSigningData(sideIndex, transcriptHash, signingBuffer);
    return Signature::signMessage(ctx, scheme.getKeyAlgorithm(), hash, privateKey, signatureBuffer, tbs);
}

void CertificateVerify::doTLSv13Verify(const CertificateVerify& certVerify, const int8_t sideIndex, HashCtx* ctx,
                                       Key* publicKey, nonstd::span<const uint8_t> transcriptHash)
{
    std::array<uint8_t, MAX_TBS_SIZE> signingBuffer;
    HashAlg hash{nullptr};

    auto hashName = certVerify.scheme.getHashAlgorithm();
    if (!casket::equals(hashName, "UNDEF"))
    {
        hash = CryptoManager::getInstance().fetchDigest(hashName);
    }

    auto tbs = ::ConstructSigningData(sideIndex, transcriptHash, signingBuffer);
    Signature::verifyMessage(ctx, certVerify.scheme.getKeyAlgorithm(), hash, publicKey, certVerify.signature, tbs);
}

} // namespace snet::tls