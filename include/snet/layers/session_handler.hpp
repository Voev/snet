#pragma once
#include <cstdint>
#include <memory>
#include <snet/layers/packet.hpp>

namespace snet::layers
{

enum PacketStatus
{
    UnknownStatus = 0,
    PacketHandled,
    Error_NoMemory,
    TcpMessageHandled,
    OutOfOrderTcpMessageBuffered,
    FIN_RSTWithNoData,
    Ignore_PacketWithNoData,
    Ignore_PacketOfClosedFlow,
    Ignore_Retransimission,
    NonIpPacket,
    NonTcpPacket,
    Error_PacketDoesNotMatchFlow,
};

template <typename SessionManagerType>
class ISessionHandler
{
public:
    using Session = typename SessionManagerType::Session;
    using Key = typename SessionManagerType::Key;

    virtual ~ISessionHandler() = default;

    virtual const char* name() const = 0;

    virtual bool createContext(Session* session) = 0;

    virtual bool destroyContext(Session* session) = 0;

    virtual PacketStatus processPacket(Session* session, layers::Packet* packet, PacketStatus status) = 0;

    void setNext(std::shared_ptr<ISessionHandler> next)
    {
        next_ = std::move(next);
    }

    virtual void setSessionManager(SessionManagerType* manager)
    {
        sessionManager_ = manager;
    }

protected:
    inline PacketStatus passToNext(Session* session, layers::Packet* packet, PacketStatus status)
    {
        if (next_)
        {
            return next_->processPacket(session, packet, status);
        }
        return status;
    }

    template <typename ContextType>
    ContextType* getContext(Session* session, size_t index = 0)
    {
        if (!sessionManager_ || !session)
            return nullptr;
        return sessionManager_->template getContext<ContextType>(session, index);
    }

    template <typename ContextType>
    bool setContext(Session* session, ContextType* ctx, size_t index = 0)
    {
        if (!sessionManager_ || !session)
            return false;
        return sessionManager_->template setContext<ContextType>(session, ctx, index);
    }

    template <typename ContextType>
    ContextType* allocateContext()
    {
        if (!sessionManager_)
            return nullptr;
        return sessionManager_->template allocateContext<ContextType>();
    }

    template <typename ContextType>
    void deallocateContext(ContextType* ctx)
    {
        if (sessionManager_)
        {
            sessionManager_->template deallocateContext<ContextType>(ctx);
        }
    }

    SessionManagerType* getSessionManager() const
    {
        return sessionManager_;
    }

private:
    std::shared_ptr<ISessionHandler> next_;
    SessionManagerType* sessionManager_{nullptr};
};

} // namespace snet::session