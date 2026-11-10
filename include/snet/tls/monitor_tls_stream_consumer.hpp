#pragma once

#include <cstdio>
#include <cstring>
#include <memory>

#include <snet/session.hpp>
#include <snet/tcp/tcp_stream.hpp>

#include <snet/tls/tls_decrypt_context.hpp>
#include <snet/tls/record_printer.hpp>

#include <casket/log/log.hpp>

namespace snet::tls
{

struct MonitorOptions
{
    bool printRecords{false};
};

struct MonitorStats
{
    size_t processedRecords{0UL};
};

template <typename SessionManagerType>
class MonitorTlsStreamConsumer final : public snet::tcp::IStreamConsumer<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;

    explicit MonitorTlsStreamConsumer(SessionManagerType* sessionManager,
                                      const MonitorOptions& options = MonitorOptions())
        : sessionManager_(sessionManager)
        , options_(options)
    {
    }

    void onStreamData(Session* session, int8_t sideIndex, snet::tcp::IStreamReader& reader) override
    {
        auto* ctx = sessionManager_->template getContext<TlsDecryptContext>(session);
        if (!ctx || !ctx->session)
            return;

        while (reader.available() > 0)
        {
            auto [data, len] = reader.peek();
            if (!data || len == 0)
                break;

            size_t consumed = 0;
            try
            {
                consumed = ctx->session->readRecords({data, len});

                ctx->session->processPendingRecords(sideIndex,
                                                    [&ctx, this](const int8_t si, Record* record)
                                                    {
                                                        if (options_.printRecords)
                                                        {
                                                            PrintRecord(si, ctx->session.get(), record);
                                                        }

                                                        stats_.processedRecords++;
                                                    });
            }
            catch (const std::exception& e)
            {
                CSK_LOG_ERROR("error processing stream with length %lu: %s", len, e.what());
                break;
            }

            if (consumed == 0)
                break;

            reader.consume(consumed);
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

    MonitorStats getStats() const
    {
        return stats_;
    }

private:
    SessionManagerType* sessionManager_{nullptr};
    MonitorOptions options_;
    MonitorStats stats_;
};

} // namespace snet::tls