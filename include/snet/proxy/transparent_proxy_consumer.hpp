#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>

#include <snet/session/session_manager.hpp>
#include <snet/tcp/tcp_stream.hpp>
#include <snet/tcp/tcp_transmit_handler.hpp>

#include <snet/proxy/proxy_context.hpp>
#include <snet/proxy/tls_decision_engine.hpp>
#include <snet/proxy/transparent_proxy_acceptor.hpp>

#include <casket/log/log.hpp>

namespace snet::proxy
{

/// Consumer split-proxy.
///
/// Жизненный цикл пары:
///   1. Waiting — TCP с клиентом установлен, ClientHello ещё не пришёл.
///   2. ClientHello приходит → копим в pair.bufferedClientHello,
///      извлекаем SNI, запускаем decision engine.
///   3. Пока Probe — downstream не перекладывает байты никуда.
///   4. Решение Bypass:
///        - открываем upstream;
///        - перекладываем ОРИГИНАЛЬНЫЙ ClientHello в upstream как есть;
///        - дальше raw splice.
///   5. Решение Mitm:
///        - открываем upstream;
///        - строим свой ClientHello к серверу через serverTls;
///        - строим свой ServerHello клиенту через clientTls;
///        - дальше TLS-терминация.
///   6. Решение Block — RST, закрытие.
template <typename SessionManagerType>
class TransparentProxyConsumer final : public snet::tcp::IStreamConsumer<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;
    using TcpConnection = snet::tcp::TcpConnection;
    using TransmitHandler = snet::tcp::TcpTransmitHandler<SessionManagerType>;
    using Acceptor = TransparentProxyAcceptor<SessionManagerType>;
    using TlsSession = snet::tls::Session;

    TransparentProxyConsumer(SessionManagerType* mgr, TransmitHandler* tx, TlsDecisionEngine* engine,
                             Acceptor* acceptor)
        : mgr_(mgr)
        , tx_(tx)
        , engine_(engine)
        , acceptor_(acceptor)
    {
    }

    void onStreamData(Session* session, int8_t /*side*/, snet::tcp::IStreamReader& reader) override
    {
        auto* ctx = mgr_->template getContext<ProxyContext>(session);
        if (!ctx || !ctx->pair)
            return;

        auto& pair = *ctx->pair;

        switch (pair.phase)
        {
        case PairPhase::Waiting:
            std::cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;
            handleWaiting(session, *ctx, pair, reader);
            break;

        case PairPhase::Probing:
        {
            // Keep buffering while probe is in flight: client may retransmit
            // ClientHello or start sending early data. All of it must be
            // flushed to upstream by pushToUpstream() after the decision.
            while (reader.available() > 0)
            {
                auto [data, len] = reader.peek();
                if (!data || len == 0)
                    break;
                pair.bufferedClientHello.insert(pair.bufferedClientHello.end(), data, data + len);
                reader.consume(len);
            }
            break;
        }
        case PairPhase::Splice:
            forwardRaw(session, *ctx, pair, reader);
            break;

        case PairPhase::Mitm:
            forwardMitm(session, *ctx, pair, reader);
            break;

        case PairPhase::Closed:
            reader.consume(reader.available());
            break;
        }
    }

    void onStreamClose(Session* session, int8_t /*side*/, int /*reason*/) override
    {
        auto* ctx = mgr_->template getContext<ProxyContext>(session);
        if (!ctx || !ctx->pair)
            return;

        auto& pair = *ctx->pair;
        pair.phase = PairPhase::Closed;

        // Закрываем peer-сессию.
        const uint32_t otherKey = ctx->isDownstream ? pair.upstreamKey : pair.downstreamKey;
        closeOther(otherKey);

        printSummary(pair);
    }

    void onStreamGap(Session*, int8_t, uint32_t missingBytes) override
    {
        CSK_LOG_WARNING("TransparentProxy: gap %u bytes", missingBytes);
    }

private:
    // ─────────────────────────────────────────────────────────────────
    // Фаза Waiting: копим ClientHello, определяем SNI, запускаем probe.
    // ─────────────────────────────────────────────────────────────────
    void handleWaiting(Session* session, ProxyContext& ctx, ProxyPair& pair, snet::tcp::IStreamReader& reader)
    {
        if (!ctx.isDownstream)
            return;

        // Копим всё, что пришло.
        while (reader.available() > 0)
        {
            auto [data, len] = reader.peek();
            if (!data || len == 0)
                break;
            pair.bufferedClientHello.insert(pair.bufferedClientHello.end(), data, data + len);
            reader.consume(len);
        }

        // Пробуем извлечь SNI из накопленного.
        if (pair.clientSni.empty())
        {
            auto sni = std::string("test"); // extractSniFromClientHello(pair.bufferedClientHello);
            if (sni.empty())
                return; // ждём ещё байт
            pair.clientSni = std::move(sni);
            CSK_LOG_DEBUG("Proxy: SNI=%s", pair.clientSni.c_str());
        }

        // Запускаем решение.
        pair.phase = PairPhase::Probing;
        engine_->request(pair.clientSni,
                         pair.serverIP,
                         pair.serverPort,
                         [this, session](InspectionDecision d)
                         {
                             onDecision(session, d);
                         });
    }

    // ─────────────────────────────────────────────────────────────────
    // Решение получено. Применяем.
    // ─────────────────────────────────────────────────────────────────
    void onDecision(Session* session, InspectionDecision d)
    {
        auto* ctx = mgr_->template getContext<ProxyContext>(session);
        if (!ctx || !ctx->pair)
            return;
        auto& pair = *ctx->pair;

        pair.decision = d;

        switch (d)
        {
        case InspectionDecision::Bypass:
        {
            pair.phase = PairPhase::Splice;
            acceptor_->openUpstream(session);
            if (!pair.bufferedClientHello.empty())
            {
                pushToUpstream(session, *ctx, pair, pair.bufferedClientHello);
                pair.bufferedClientHello.clear();
            }
            break;
        }
        case InspectionDecision::Mitm:
            pair.phase = PairPhase::Mitm;
            acceptor_->openUpstream(session);
            startMitm(session, *ctx, pair);
            break;

        case InspectionDecision::Block:
            pair.phase = PairPhase::Closed;
            blockFlow(session, *ctx, pair);
            break;
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Открытие MITM-сессии. Заготовка — полноценная логика TLS-
    // терминации делается отдельно, здесь только инфраструктура.
    // ─────────────────────────────────────────────────────────────────
    void startMitm(Session* session, ProxyContext& ctx, ProxyPair& pair)
    {
        (void)session;
        (void)ctx;

        // Создаём два tls::Session, работающих в active-режиме.
        pair.clientTls = std::make_unique<TlsSession>(pair.pool);
        pair.clientTls->setMonitor(false);

        pair.serverTls = std::make_unique<TlsSession>(pair.pool);
        pair.serverTls->setMonitor(false);

        // TODO: построить ServerHello/Certificate/Finished для клиента
        //       и ClientHello для сервера. Это отдельная большая тема.
        //
        // См. Session::constructClientHello / constructServerHello
        // (второго в публичном API нет — придётся генерировать
        //  ServerHello вручную или добавить в Session).

        CSK_LOG_INFO("Proxy: MITM enabled for SNI=%s", pair.clientSni.c_str());
    }

    // ─────────────────────────────────────────────────────────────────
    // Bypass: перекладывание байтов как есть.
    // ─────────────────────────────────────────────────────────────────
    void forwardRaw(Session* session, ProxyContext& ctx, ProxyPair& pair, snet::tcp::IStreamReader& reader)
    {
        (void)session;

        // Определяем целевую сессию.
        const uint32_t dstKey = ctx.isDownstream ? pair.upstreamKey : pair.downstreamKey;
        auto* dstSession = mgr_->find(dstKey);
        if (!dstSession)
            return;

        auto* dstConn = mgr_->template getContext<TcpConnection>(dstSession);
        if (!dstConn || dstConn->closed || !dstConn->txRing)
            return;

        while (reader.available() > 0)
        {
            const size_t free = dstConn->txRing->freeSpace();
            if (free == 0)
                break;

            auto [data, len] = reader.peek();
            if (!data || len == 0)
                break;

            utils::printHex(std::cout, {data, len}, "TCP stream");

            const size_t chunk = std::min(len, free);
            const size_t written = dstConn->txRing->write(data, chunk);
            reader.consume(written);

            if (ctx.isDownstream)
                pair.bytesToServer += written;
            else
                pair.bytesToClient += written;

            if (written < chunk)
                break;
        }

        if (tx_)
            tx_->pump(dstSession);
    }

    // ─────────────────────────────────────────────────────────────────
    // MITM: расшифровка, обработка, перешифрование.
    // Заготовка — полная логика сложнее, здесь только структура.
    // ─────────────────────────────────────────────────────────────────
    void forwardMitm(Session* session, ProxyContext& ctx, ProxyPair& pair, snet::tcp::IStreamReader& reader)
    {
        (void)session;
        (void)ctx;
        (void)pair;
        // TODO:
        //   1. Скормить reader в pair.clientTls (или serverTls в зав. от ctx).
        //   2. processPendingRecords с обработчиком:
        //        - ApplicationData → расшифровать → передать в другую сессию.
        //        - Handshake → обработать (KeyUpdate и т.д.).
        //   3. Забрать outgoing из другой сессии, записать в её txRing.
        //
        // Сейчас — ничего, MITM реализуется отдельным шагом.
        reader.consume(reader.available());
    }

    // ─────────────────────────────────────────────────────────────────
    // Перекладываем произвольный буфер в upstream txRing.
    // Используется при bypass для отправки оригинального ClientHello.
    // ─────────────────────────────────────────────────────────────────
    void pushToUpstream(Session* session, ProxyContext& ctx, ProxyPair& pair, const std::vector<uint8_t>& bytes)
    {
        (void)session;
        (void)ctx;

        if (bytes.empty())
            return;

        const uint32_t dstKey = ctx.isDownstream ? pair.upstreamKey : pair.downstreamKey;
        auto* dstSession = mgr_->find(dstKey);
        if (!dstSession)
            return;

        auto* dstConn = mgr_->template getContext<TcpConnection>(dstSession);
        if (!dstConn || !dstConn->txRing)
            return;

        // Пишем всё, что влезает. Остаток отправится позже —
        // но т.к. ClientHello обычно < MSS, переполнения не будет.
        size_t off = 0;
        while (off < bytes.size())
        {
            const size_t free = dstConn->txRing->freeSpace();
            if (free == 0)
                break;

            const size_t chunk = std::min(free, bytes.size() - off);
            const size_t w = dstConn->txRing->write(bytes.data() + off, chunk);
            off += w;
            pair.bytesToServer += w;
            if (w < chunk)
                break;
        }

        if (tx_)
            tx_->pump(dstSession);
    }

    void blockFlow(Session* session, ProxyContext& ctx, ProxyPair& pair)
    {
        auto* conn = mgr_->template getContext<TcpConnection>(session);
        if (conn)
        {
            auto out = snet::tcp::TcpStateMachine::onAppAbort(*conn);
            if (out.type == snet::tcp::TcpOutput::Type::SendReset)
            {
                conn->pendingOutput = out;
                conn->hasPendingOutput = true;
                if (tx_)
                    tx_->pump(session);
            }
        }
        (void)ctx;
        (void)pair;
    }

    void closeOther(uint32_t key)
    {
        auto* other = mgr_->find(key);
        if (!other)
            return;

        auto* otherConn = mgr_->template getContext<TcpConnection>(other);
        if (!otherConn || otherConn->closed)
            return;

        auto out = snet::tcp::TcpStateMachine::onAppClose(*otherConn);
        if (out.type == snet::tcp::TcpOutput::Type::Send || out.type == snet::tcp::TcpOutput::Type::SendReset)
        {
            otherConn->pendingOutput = out;
            otherConn->hasPendingOutput = true;
            if (tx_)
                tx_->pump(other);
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Извлечение SNI из накопленного буфера ClientHello.
    // Обёртка: находит TLS record с handshake ClientHello,
    // затем вызывает extractSni по расширениям.
    // ─────────────────────────────────────────────────────────────────
    static std::string extractSniFromClientHello(const std::vector<uint8_t>& buf);

    void printSummary(const ProxyPair& pair) const
    {
        printf("\n═══ TLS proxy session summary ═══\n");
        printf("  %s:%u <-> %s:%u\n",
               pair.clientIP.toString().c_str(),
               pair.clientPort,
               pair.serverIP.toString().c_str(),
               pair.serverPort);
        printf("  SNI:    %s\n", pair.clientSni.empty() ? "(none)" : pair.clientSni.c_str());
        printf("  Decision: %s\n",
               pair.decision == InspectionDecision::Mitm    ? "MITM"
               : pair.decision == InspectionDecision::Block ? "Block"
                                                            : "Bypass");
        printf("  Bytes:  c->s %lu, s->c %lu\n", pair.bytesToServer, pair.bytesToClient);
        printf("═════════════════════════════════\n\n");
    }

    SessionManagerType* mgr_;
    TransmitHandler* tx_;
    TlsDecisionEngine* engine_;
    Acceptor* acceptor_;
};

} // namespace snet::proxy