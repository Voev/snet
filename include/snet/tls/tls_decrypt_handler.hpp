#pragma once

#include <snet/session.hpp>

#include <snet/tls/record_pool.hpp>
#include <snet/tls/tls_decrypt_context.hpp>

#include <casket/log/log.hpp>

namespace snet::tls
{

template <typename SessionManagerType>
class TlsDecryptHandler : public snet::session::ISessionHandler<SessionManagerType>
{
public:
    using SessionType = typename SessionManagerType::Session;

    TlsDecryptHandler(RecordPool* recordPool)
        : recordPool_(recordPool)
    {
    }

    const char* name() const override
    {
        return "TlsDecryptHandler";
    }

    bool createContext(SessionType* session) override
    {
        if (!session)
        {
            return false;
        }

        auto* tls = this->template allocateContext<TlsDecryptContext>();
        if (!tls)
        {
            CSK_LOG_ERROR("cannot allocate TlsDecryptionContext");
            return false;
        }

        tls->session = std::make_unique<snet::tls::Session>(*recordPool_);

        if (!this->template setContext<TlsDecryptContext>(session, tls))
        {
            this->template deallocateContext<TlsDecryptContext>(tls);
            CSK_LOG_ERROR("failed to set TlsDecryptionContext");
            return false;
        }
        return true;
    }

    bool destroyContext(SessionType* session) override
    {
        if (!session)
        {
            return false;
        }

        auto* tls = this->template getContext<TlsDecryptContext>(session);
        if (tls)
        {
            this->template removeContext<TlsDecryptContext>(session);
            this->template deallocateContext<TlsDecryptContext>(tls);
        }

        return true;
    }

    layers::PacketStatus processPacket(SessionType* session, layers::Packet* packet, layers::PacketStatus status) override
    {
        return this->passToNext(session, packet, status);
    }

private:
    RecordPool* recordPool_{nullptr};
};

} // namespace snet::tcp