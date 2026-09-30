#pragma once

#include <snet/session.hpp>

#include <snet/tls/record_pool.hpp>
#include <snet/tls/tls_decrypt_context.hpp>

#include <casket/log/log.hpp>

namespace snet::tls
{

template <typename SessionManagerType>
class TlsDecryptCtxFactory : public snet::session::ISessionCtxFactory<SessionManagerType>
{
public:
    using SessionType = typename SessionManagerType::Session;

    TlsDecryptCtxFactory(RecordPool* recordPool)
        : recordPool_(recordPool)
    {
        assert(recordPool_ != nullptr);
    }

    const char* name() const override
    {
        return "TlsDecryptFactory";
    }

    bool createContext(SessionType* session) override
    {
        if (!session)
        {
            return false;
        }

        auto* ctx = this->template allocateContext<TlsDecryptContext>();
        if (!ctx)
        {
            CSK_LOG_ERROR("cannot allocate TlsDecryptionContext");
            return false;
        }

        if (!this->template setContext<TlsDecryptContext>(session, ctx))
        {
            this->template deallocateContext<TlsDecryptContext>(ctx);
            CSK_LOG_ERROR("failed to set TlsDecryptionContext");
            return false;
        }

        ctx->session = std::make_unique<snet::tls::Session>(*recordPool_);
        return true;
    }

    bool destroyContext(SessionType* session) override
    {
        if (!session)
        {
            return false;
        }

        auto* ctx = this->template getContext<TlsDecryptContext>(session);
        if (ctx)
        {
            this->template removeContext<TlsDecryptContext>(session);
            this->template deallocateContext<TlsDecryptContext>(ctx);
        }
        return true;
    }

private:
    RecordPool* recordPool_{nullptr};
};

} // namespace snet::tls