#pragma once
#include <cstddef>
#include <utility>

namespace snet::session
{

template <typename SessionManagerType>
class ISessionCtxFactory
{
public:
    using Session = typename SessionManagerType::Session;

    virtual ~ISessionCtxFactory() = default;

    virtual const char* name() const = 0;

    virtual bool createContext(Session* session) = 0;

    virtual bool destroyContext(Session* session) = 0;

    virtual void setSessionManager(SessionManagerType* manager)
    {
        sessionManager_ = manager;
    }

    SessionManagerType* getSessionManager() const
    {
        return sessionManager_;
    }

protected:

    template <typename ContextType>
    ContextType* getContext(Session* session, size_t index = 0) const
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
        {
            return nullptr;
        }
        return sessionManager_->template allocateContext<ContextType>();
    }

    template <typename ContextType, typename... Args>
    ContextType* allocateContext(Args&&... args)
    {
        if (!sessionManager_)
        {
            return nullptr;
        }
        return sessionManager_->template allocateContext<ContextType>(std::forward<Args>(args)...);
    }

    template <typename ContextType>
    ContextType* removeContext(Session* session, size_t index = 0)
    {
        if (!sessionManager_)
        {
            return nullptr;
        }
        return sessionManager_->template removeContext<ContextType>(session, index);
    }

    template <typename ContextType>
    void deallocateContext(ContextType* ctx)
    {
        if (sessionManager_)
        {
            sessionManager_->template deallocateContext<ContextType>(ctx);
        }
    }

private:
    SessionManagerType* sessionManager_{nullptr};
};

} // namespace snet::session