#pragma once
#include <snet/session/session_manager.hpp>

#include <snet/tcp/tcp_stream.hpp>
#include <casket/log/log.hpp>

namespace echo
{

using namespace snet::layers;

template <typename SessionManagerType>
class EchoConsumer : public snet::tcp::IStreamConsumer<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;
    using TcpConnection = snet::tcp::TcpConnection;

    explicit EchoConsumer(SessionManagerType* mgr)
        : mgr_(mgr)
    {
    }

    void onStreamData(Session* session, int8_t side, snet::tcp::IStreamReader& reader) override
    {
        (void)side;

        auto* conn = mgr_->template getContext<TcpConnection>(session);
        if (!conn || conn->closed)
            return;
        if (!conn->txRing)
            return;

        while (reader.available() > 0)
        {
            auto [data, len] = reader.peek();
            if (!data || len == 0)
                break;

            const size_t free = conn->txRing->freeSpace();
            if (free == 0)
            {
                CSK_LOG_WARNING("Echo: txRing full, backpressure");
                break;
            }

            const size_t toEcho = std::min(len, free);
            const size_t written = conn->txRing->write(data, toEcho);
            reader.consume(written);

            CSK_LOG_DEBUG("Echo: echoed %zu bytes", written);

            if (written < toEcho)
                break;
        }
    }

    void onStreamClose(Session* session, int8_t side, int reason) override
    {
        (void)side;

        auto* conn = mgr_->template getContext<TcpConnection>(session);
        if (!conn)
            return;

        CSK_LOG_DEBUG(
            "Echo: stream closed (reason=%d, state=%s)", reason, std::string(tcpStateName(conn->state)).c_str());
    }

    void onStreamGap(Session* session, int8_t side, uint32_t missingBytes) override
    {
        (void)session;
        (void)side;
        CSK_LOG_WARNING("Echo: gap of %u bytes", missingBytes);
    }

private:
    SessionManagerType* mgr_;
};

} // namespace echo