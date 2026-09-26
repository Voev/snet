#pragma once

#include <cstdio>
#include <cstring>
#include <memory>

#include <snet/session.hpp>
#include <snet/tcp/tcp_stream.hpp>

#include <snet/tls/tls_decrypt_context.hpp>
#include <snet/tls/record_printer.hpp>
#include <snet/tls/secret_node_manager.hpp>

#include <casket/log/log.hpp>

namespace snet::tls
{

struct TlsDecryptOptions
{
    bool printRecords{false};
};

struct TlsDecryptStats
{
    uint64_t decryptedRecords{0U};
};

template <typename SessionManagerType>
class TlsDecryptStreamConsumer final : public snet::tcp::IStreamConsumer<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;

    explicit TlsDecryptStreamConsumer(SessionManagerType* sessionManager, SecretNodeManager* secretManager,
                                      const TlsDecryptOptions& options = TlsDecryptOptions())
        : sessionManager_(sessionManager)
        , secretManager_(secretManager)
        , options_(options)
    {
    }

    void onStreamData(Session* session, int8_t sideIndex, snet::tcp::IStreamReader& reader) override
    {
        auto* ctx = sessionManager_->template getContext<TlsDecryptContext>(session);
        if (!ctx)
        {
            return;
        }

        auto stream = reader.peek();
        try
        {
            ctx->session->readRecords({stream.first, stream.second});
            ctx->session->processPendingRecords(
                sideIndex,
                [&ctx, this](const int8_t sideIndex, Record* record)
                {
                    if (options_.printRecords)
                    {
                        PrintRecord(sideIndex, ctx->session.get(), record);
                    }

                    if (sessionManager_ && record->getHandshakeType() == HandshakeType::ClientHelloCode)
                    {
                        auto& clientHello = record->getHandshake<ClientHello>();
                        ClientRandom random{clientHello.random.begin(), clientHello.random.end()};

                        auto secrets = secretManager_->getSecretNode(random);
                        if (secrets)
                        {
                            ctx->session->setSecrets(secrets);
                        }
                    }

                    if (record->isPlaintext())
                    {
                        ctx->decryptedRecords++;
                        stats_.decryptedRecords++;
                    }
                });
        }
        catch (const std::exception& e)
        {
            CSK_LOG_ERROR("error processing stream with length %lu: %s", stream.second, e.what());
        }
    }

    void onStreamClose(Session* session, int8_t sideIndex, int reason) override
    {
        CSK_LOG_WARNING("session=%p, side=%d, reason=%d", session, sideIndex, reason);
    }

    void onStreamGap(Session* session, int8_t sideIndex, uint32_t missingBytes) override
    {
        CSK_LOG_WARNING("session=%p, side=%d, gap=%u bytes", session, sideIndex, missingBytes);
    }

    TlsDecryptStats getStats() const
    {
        return stats_;
    }

private:
    SessionManagerType* sessionManager_{nullptr};
    SecretNodeManager* secretManager_{nullptr};
    TlsDecryptOptions options_;
    TlsDecryptStats stats_;
};

} // namespace snet::tls