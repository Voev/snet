#pragma once
#include <cstdint>
#include <memory>
#include <snet/layers/packet.hpp>
#include <snet/layers/packet_status.hpp>

namespace snet::session
{

template <typename SessionManagerType>
class ISessionHandler
{
public:
    using Session = typename SessionManagerType::Session;
    using Key = typename SessionManagerType::Key;

    virtual ~ISessionHandler() = default;

    virtual const char* name() const = 0;

    virtual layers::PacketStatus processPacket(Session* session, layers::Packet* packet, layers::PacketStatus status) = 0;

    void setNext(std::shared_ptr<ISessionHandler> next)
    {
        next_ = std::move(next);
    }

    virtual void setSessionManager(SessionManagerType* manager)
    {
        sessionManager_ = manager;
    }

    SessionManagerType* getSessionManager() const
    {
        return sessionManager_;
    }

protected:
    inline layers::PacketStatus passToNext(Session* session, layers::Packet* packet, layers::PacketStatus status)
    {
        if (next_)
        {
            return next_->processPacket(session, packet, status);
        }
        return status;
    }

    template <typename ContextType>
    ContextType* getContext(Session* session, size_t index = 0) const
    {
        if (!sessionManager_ || !session)
            return nullptr;
        return sessionManager_->template getContext<ContextType>(session, index);
    }

private:
    std::shared_ptr<ISessionHandler> next_;
    SessionManagerType* sessionManager_{nullptr};
};

} // namespace snet::session