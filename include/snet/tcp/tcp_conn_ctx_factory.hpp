#pragma once

#include <snet/session/session_ctx_factory.hpp>
#include <snet/tcp/tcp_types.hpp>
#include <snet/tcp/tcp_stream.hpp>

#include <casket/log/log.hpp>

namespace snet::tcp
{

/// @brief Factory that creates TWO TcpConnection contexts per session:
///        idx 0 — client -> server direction
///        idx 1 — server -> client direction
///
/// Each context owns its own RX and TX rings, acquired from pools.
/// This is required because TCP is full-duplex: both directions have
/// independent sequence spaces (rcvNxt, sndNxt).
template <typename SessionManagerType>
class TcpConnectionCtxFactory final
    : public snet::session::ISessionCtxFactory<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;
    using TcpConnection = snet::tcp::TcpConnection;

    TcpConnectionCtxFactory(RxRingPool* rxPool = nullptr,
                            TxRingPool* txPool = nullptr)
        : rxPool_(rxPool)
        , txPool_(txPool)
    {
    }

    const char* name() const override
    {
        return "TcpConnectionCtxFactory";
    }

    bool createContext(Session* session) override
    {
        if (!session)
            return false;

        // Reject if any context already exists — createContext must be
        // called exactly once per session by the pipeline.
        if (this->template getContext<TcpConnection>(session, kClientSide) ||
            this->template getContext<TcpConnection>(session, kServerSide))
        {
            CSK_LOG_WARNING("TcpConnectionCtxFactory: contexts already exist");
            return true;
        }

        if (!createOne(session, kClientSide))
        {
            CSK_LOG_ERROR("TcpConnectionCtxFactory: ctx[0] failed");
            return false;
        }

        if (!createOne(session, kServerSide))
        {
            CSK_LOG_ERROR("TcpConnectionCtxFactory: ctx[1] failed, rolling back");
            destroyOne(session, kClientSide);
            return false;
        }

        CSK_LOG_DEBUG("TcpConnectionCtxFactory: created both contexts "
                      "(rxPool=%p, txPool=%p)",
                      static_cast<void*>(rxPool_),
                      static_cast<void*>(txPool_));

        return true;
    }

    bool destroyContext(Session* session) override
    {
        if (!session)
            return false;

        destroyOne(session, kServerSide);
        destroyOne(session, kClientSide);

        return true;
    }

private:

    bool createOne(Session* session, size_t idx)
    {
        auto* ctx = this->template allocateContext<TcpConnection>();
        if (!ctx)
        {
            CSK_LOG_ERROR("TcpConnectionCtxFactory: cannot allocate ctx[%zu]", idx);
            return false;
        }

        // Reset FSM state — but keep ring pointers null (we'll set them next).
        ctx->reset();

        // RX ring
        if (rxPool_)
        {
            RxRingBuffer* rx = rxPool_->acquire();
            if (!rx)
            {
                CSK_LOG_WARNING("TcpConnectionCtxFactory: RX pool exhausted "
                                "(capacity=%zu)",
                                rxPool_->capacity());
                this->template deallocateContext<TcpConnection>(ctx);
                return false;
            }
            rx->reset();
            ctx->rxRing = rx;
        }

        // TX ring
        if (txPool_)
        {
            TxRingBuffer* tx = txPool_->acquire();
            if (!tx)
            {
                CSK_LOG_WARNING("TcpConnectionCtxFactory: TX pool exhausted "
                                "(capacity=%zu)",
                                txPool_->capacity());
                // Roll back RX
                if (ctx->rxRing && rxPool_)
                {
                    ctx->rxRing->reset();
                    rxPool_->release(ctx->rxRing);
                    ctx->rxRing = nullptr;
                }
                this->template deallocateContext<TcpConnection>(ctx);
                return false;
            }
            tx->reset();
            ctx->txRing = tx;
        }

        // Install in session
        if (!this->template setContext<TcpConnection>(session, ctx, idx))
        {
            // Roll back rings
            if (ctx->rxRing && rxPool_)
            {
                ctx->rxRing->reset();
                rxPool_->release(ctx->rxRing);
                ctx->rxRing = nullptr;
            }
            if (ctx->txRing && txPool_)
            {
                ctx->txRing->reset();
                txPool_->release(ctx->txRing);
                ctx->txRing = nullptr;
            }
            this->template deallocateContext<TcpConnection>(ctx);
            return false;
        }

        CSK_LOG_DEBUG("TcpConnectionCtxFactory: ctx[%zu] created "
                      "(rx=%p, tx=%p)",
                      idx,
                      static_cast<void*>(ctx->rxRing),
                      static_cast<void*>(ctx->txRing));

        return true;
    }

    void destroyOne(Session* session, size_t idx)
    {
        auto* ctx = this->template getContext<TcpConnection>(session, idx);
        if (!ctx)
            return;

        if (ctx->rxRing && rxPool_)
        {
            ctx->rxRing->reset();
            rxPool_->release(ctx->rxRing);
            ctx->rxRing = nullptr;
        }

        if (ctx->txRing && txPool_)
        {
            ctx->txRing->reset();
            txPool_->release(ctx->txRing);
            ctx->txRing = nullptr;
        }

        this->template removeContext<TcpConnection>(session, idx);
        this->template deallocateContext<TcpConnection>(ctx);

        CSK_LOG_DEBUG("TcpConnectionCtxFactory: ctx[%zu] destroyed", idx);
    }

private:
    RxRingPool* rxPool_{nullptr};
    TxRingPool* txPool_{nullptr};
};

} // namespace snet::tcp