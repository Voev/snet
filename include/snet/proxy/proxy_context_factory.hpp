#pragma once

#include <snet/session/session_ctx_factory.hpp>

#include <casket/log/log.hpp>

#include "proxy_context.hpp"

namespace snet::proxy
{

template <typename SessionManagerType>
class ProxyContextFactory final
    : public snet::session::ISessionCtxFactory<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;

    const char* name() const override { return "ProxyContextFactory"; }

    bool createContext(Session* session) override
    {
        if (!session)
            return false;

        auto* ctx = this->template allocateContext<ProxyContext>();
        if (!ctx)
        {
            CSK_LOG_ERROR("ProxyContextFactory: allocateContext failed");
            return false;
        }

        *ctx = ProxyContext{};

        if (!this->template setContext<ProxyContext>(session, ctx))
        {
            this->template deallocateContext<ProxyContext>(ctx);
            CSK_LOG_ERROR("ProxyContextFactory: setContext failed");
            return false;
        }

        return true;
    }

    bool destroyContext(Session* session) override
    {
        if (!session)
            return false;

        auto* ctx = this->template getContext<ProxyContext>(session);
        if (!ctx)
            return true;

        this->template removeContext<ProxyContext>(session);
        this->template deallocateContext<ProxyContext>(ctx);
        return true;
    }
};

} // namespace snet::proxy