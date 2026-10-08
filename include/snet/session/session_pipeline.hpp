#pragma once

#include <cstdio>
#include <memory>
#include <ostream>
#include <string>
#include <type_traits>
#include <vector>

#include <casket/log/log.hpp>

#include <snet/session/session_handler.hpp>

namespace snet::session
{

template <typename SessionManagerType>
class SessionPipeline
{
public:
    using Session = typename SessionManagerType::Session;
    using Handler = ISessionHandler<SessionManagerType>;
    using HandlerPtr = std::shared_ptr<Handler>;

    SessionPipeline() = default;

    explicit SessionPipeline(SessionManagerType* manager)
        : sessionManager_(manager)
    {
    }

    SessionPipeline(const SessionPipeline&) = delete;
    SessionPipeline& operator=(const SessionPipeline&) = delete;

    void setSessionManager(SessionManagerType* manager)
    {
        sessionManager_ = manager;
        for (auto& handler : handlers_)
            handler->setSessionManager(manager);
    }

    [[nodiscard]] SessionManagerType* getSessionManager() const noexcept
    {
        return sessionManager_;
    }

    SessionPipeline& add(HandlerPtr handler)
    {
        if (!handler)
            return *this;

        if (sessionManager_)
            handler->setSessionManager(sessionManager_);

        handlers_.push_back(std::move(handler));
        return *this;
    }

    template <typename HandlerType, typename... Args>
    SessionPipeline& addHandler(Args&&... args)
    {
        static_assert(std::is_base_of_v<Handler, HandlerType>, "HandlerType must derive from ISessionHandler");

        auto handler = std::make_shared<HandlerType>(std::forward<Args>(args)...);
        return add(std::move(handler));
    }

    bool insertHandler(size_t position, HandlerPtr handler)
    {
        if (position > handlers_.size() || !handler)
            return false;

        if (sessionManager_)
            handler->setSessionManager(sessionManager_);

        handlers_.insert(handlers_.begin() + position, std::move(handler));
        return true;
    }

    bool removeHandler(const std::string& name)
    {
        for (size_t i = 0; i < handlers_.size(); ++i)
        {
            if (handlers_[i]->name() == name)
            {
                handlers_.erase(handlers_.begin() + i);
                return true;
            }
        }
        return false;
    }

    void clear() noexcept
    {
        handlers_.clear();
    }

    [[nodiscard]] size_t size() const noexcept
    {
        return handlers_.size();
    }
    [[nodiscard]] bool empty() const noexcept
    {
        return handlers_.empty();
    }

    [[nodiscard]] HandlerPtr getFirst() const noexcept
    {
        return handlers_.empty() ? nullptr : handlers_.front();
    }

    [[nodiscard]] HandlerPtr getLast() const noexcept
    {
        return handlers_.empty() ? nullptr : handlers_.back();
    }

    template <typename T>
    T* findHandler() const
    {
        static_assert(std::is_base_of_v<Handler, T>, "T must derive from ISessionHandler");

        for (auto& handler : handlers_)
        {
            if (auto* casted = dynamic_cast<T*>(handler.get()))
                return casted;
        }
        return nullptr;
    }

    Handler* findHandler(const std::string& name) const
    {
        for (auto& handler : handlers_)
        {
            if (handler->name() == name)
                return handler.get();
        }
        return nullptr;
    }

    layers::PacketStatus processPacket(Session* session, layers::Packet* packet)
    {
        using namespace snet::layers;
        
        PacketStatus status = PacketStatus::drop(PacketReason::InvalidParameters);

        if (handlers_.empty() || !session || !packet)
        {
            return status;
        }

        for (auto& h : handlers_)
        {
            auto next = h->processPacket(session, packet, status);

            CSK_LOG_DEBUG("pipeline: %s -> {%s, %s}", h->name(), toString(next.verdict), toString(next.reason));

            status = next;
        }

        return status;
    }

    void printChain(std::ostream& os) const
    {
        os << "Session pipeline: ";
        if (handlers_.empty())
        {
            os << "(empty)\n";
            return;
        }
        for (size_t i = 0; i < handlers_.size(); ++i)
        {
            if (i > 0)
                os << " -> ";
            os << handlers_[i]->name();
        }
        os << '\n';
    }

private:
    std::vector<HandlerPtr> handlers_;
    SessionManagerType* sessionManager_{nullptr};
};

} // namespace snet::session