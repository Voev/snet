#pragma once

#include <snet/session/session_ctx_factory.hpp>
#include <snet/tls/record_pool.hpp>
#include <casket/log/log.hpp>

#include "probe_context.hpp"

namespace snet::probe
{

template <typename SessionManagerType>
class ProbeContextFactory final : public snet::session::ISessionCtxFactory<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;

    ProbeContextFactory() = default;

    const char* name() const override { return "ProbeContextFactory"; }

    bool createContext(Session* session) override
    {
        if (!session)
            return false;

        auto* ctx = this->template allocateContext<ProbeContext>();
        if (!ctx)
        {
            CSK_LOG_ERROR("ProbeContextFactory: allocateContext failed");
            return false;
        }

        if (!this->template setContext<ProbeContext>(session, ctx))
        {
            this->template deallocateContext<ProbeContext>(ctx);
            CSK_LOG_ERROR("ProbeContextFactory: setContext failed");
            return false;
        }

        return true;
    }

    bool destroyContext(Session* session) override
    {
        if (!session)
            return false;

        auto* ctx = this->template getContext<ProbeContext>(session);
        if (!ctx)
            return true;

        this->template removeContext<ProbeContext>(session);
        this->template deallocateContext<ProbeContext>(ctx);
        return true;
    }
};

} // namespace snet::probe