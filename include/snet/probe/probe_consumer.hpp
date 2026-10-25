#pragma once

#include <snet/tcp/tcp_stream.hpp>
#include <snet/tls/session.hpp>
#include <snet/tls/record.hpp>
#include <snet/tls/msgs/handshake_message.hpp>
#include <snet/tls/record_printer.hpp>

#include <snet/probe/probe_context.hpp>
#include <snet/probe/probe_handle.hpp>
#include <snet/probe/probe_result.hpp>

#include <casket/log/log.hpp>

namespace snet::probe
{

/// @brief Consumes probe stream data: parses TLS, extracts Certificate,
///        invokes the probe callback.
template <typename SessionManagerType>
class ProbeStreamConsumer : public snet::tcp::IStreamConsumer<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;

    explicit ProbeStreamConsumer(SessionManagerType& mgr) : mgr_(mgr) {}

    void onStreamData(Session* session, int8_t /*side*/,
                      snet::tcp::IStreamReader& reader) override
    {
        auto* probe = mgr_.template getContext<ProbeContext>(session);
        if (!probe || !probe->tls)
            return;

        if (probe->done.load())
        {
            reader.consume(reader.available());
            return;
        }

        auto [ptr, len] = reader.peek();
        if (ptr && len > 0)
        {
            probe->tls->readRecords({ptr, static_cast<size_t>(len)});
            reader.consume(len);

            constexpr int8_t kServerSide = 1;

            probe->tls->processPendingRecords(kServerSide,
                [&](int8_t side, tls::Record* rec)
                {
                    using namespace snet::tls;

                    if (rec->getType() != RecordType::Handshake)
                        return;

                    tls::PrintRecord(side, probe->tls.get(), rec);

                    switch (rec->getHandshakeType())
                    {
                    case HandshakeType::ServerHelloCode:
                    {
                        const auto& sh = rec->getHandshake<ServerHello>();
                        probe->tls->processServerHello(sh);

                        probe->result.version     = probe->tls->getVersion();
                        probe->result.cipherSuite = probe->tls->getInfo().cipherSuite;
                        break;
                    }
                    case HandshakeType::CertificateCode:
                    {
                        // TODO: extractChain(rec->getHandshake<Certificate>())
                        probe->result.status = ProbeResult::Status::Ok;
                        finish(*probe);
                        break;
                    }
                    default:
                        break;
                    }
                });
        }
    }

    void onStreamClose(Session* session, int8_t, int) override
    {
        auto* probe = mgr_.template getContext<ProbeContext>(session);
        if (!probe || probe->done.load())
            return;

        probe->result.status = probe->result.chain.empty()
            ? ProbeResult::Status::NoCertificate
            : ProbeResult::Status::Ok;
        finish(*probe);
    }

    void onStreamGap(Session* /*session*/, int8_t /*side*/, uint32_t /*missingBytes*/) override
    {
        // probe: gaps are unlikely (server sends sequential records);
        // if a gap occurs, we just wait for the missing bytes to be retransmitted.
    }

private:
    void finish(ProbeContext& probe)
    {
        if (probe.done.exchange(true))
            return;

        if (probe.cb)
            probe.cb(std::move(probe.result));

        if (auto h = probe.handle.lock())
            h->complete();
    }

    SessionManagerType& mgr_;
};

} // namespace snet::probe