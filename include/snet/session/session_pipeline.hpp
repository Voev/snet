#pragma once

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <snet/session/session_handler.hpp>

namespace snet::session
{

template <typename SessionManagerType>
class SessionPipeline
{
public:
    using Session = typename SessionManagerType::Session;
    using Handler = ISessionHandler<SessionManagerType>;
    using Strategy = std::shared_ptr<Handler>;

    SessionPipeline() = default;

    explicit SessionPipeline(SessionManagerType* manager)
        : sessionManager_(manager)
    {
    }

    void setSessionManager(SessionManagerType* manager)
    {
        sessionManager_ = manager;
        for (auto& handler : pipeline_)
        {
            handler->setSessionManager(manager);
        }
    }

    SessionPipeline& add(Strategy strategy)
    {
        if (!strategy)
        {
            return *this;
        }

        if (sessionManager_)
        {
            strategy->setSessionManager(sessionManager_);
        }

        pipeline_.push_back(std::move(strategy));
        rebuildChain();
        return *this;
    }

    template <typename HandlerType, typename... Args>
    SessionPipeline& addHandler(Args&&... args)
    {
        static_assert(std::is_base_of_v<Handler, HandlerType>,
                      "HandlerType must derive from ISessionHandler");

        auto handler = std::make_shared<HandlerType>(std::forward<Args>(args)...);
        return add(std::move(handler));
    }

    bool createContext(Session* session)
    {
        if (pipeline_.empty() || !session)
        {
            return false;
        }

        for (auto& handler : pipeline_)
        {
            if (!handler->createContext(session))
            {
                return false;
            }
        }
        return true;
    }

    bool destroyContext(Session* session)
    {
        if (pipeline_.empty() || !session)
        {
            return false;
        }

        bool success = true;
        for (auto it = pipeline_.rbegin(); it != pipeline_.rend(); ++it)
        {
            if (!(*it)->destroyContext(session))
            {
                success = false;
            }
        }
        return success;
    }

    layers::PacketStatus processPacket(Session* session, layers::Packet* packet)
    {
        if (pipeline_.empty() || !session || !packet)
        {
            return layers::PacketStatus::Error_NoMemory;
        }

        return pipeline_.front()->processPacket(session, packet, layers::PacketStatus::UnknownStatus);
    }

    void clear()
    {
        pipeline_.clear();
    }

    size_t size() const
    {
        return pipeline_.size();
    }

    bool empty() const
    {
        return pipeline_.empty();
    }

    Strategy getFirst() const
    {
        return pipeline_.empty() ? nullptr : pipeline_.front();
    }

    Strategy getLast() const
    {
        return pipeline_.empty() ? nullptr : pipeline_.back();
    }

    template <typename T>
    T* findHandler()
    {
        static_assert(std::is_base_of_v<Handler, T>,
                      "T must derive from ISessionHandler");

        for (auto& handler : pipeline_)
        {
            if (auto* casted = dynamic_cast<T*>(handler.get()))
            {
                return casted;
            }
        }
        return nullptr;
    }

    Handler* findHandler(const std::string& name)
    {
        for (auto& handler : pipeline_)
        {
            if (handler->name() == name)
            {
                return handler.get();
            }
        }
        return nullptr;
    }

    bool insertHandler(size_t position, Strategy strategy)
    {
        if (position > pipeline_.size() || !strategy)
        {
            return false;
        }

        if (sessionManager_)
        {
            strategy->setSessionManager(sessionManager_);
        }

        pipeline_.insert(pipeline_.begin() + position, std::move(strategy));
        rebuildChain();
        return true;
    }

    bool removeHandler(const std::string& name)
    {
        for (size_t i = 0; i < pipeline_.size(); ++i)
        {
            if (pipeline_[i]->name() == name)
            {
                pipeline_.erase(pipeline_.begin() + i);
                rebuildChain();
                return true;
            }
        }
        return false;
    }

    void printChain() const
    {
        printf("Session Pipeline: ");
        for (size_t i = 0; i < pipeline_.size(); ++i)
        {
            printf("%s", pipeline_[i]->name());
            if (i < pipeline_.size() - 1)
            {
                printf(" -> ");
            }
        }
        printf("\n");
    }

    struct PipelineStats
    {
        size_t totalHandlers{0};
        std::vector<std::string> handlerNames;
    };

    PipelineStats getStats() const
    {
        PipelineStats stats;
        stats.totalHandlers = pipeline_.size();
        stats.handlerNames.reserve(pipeline_.size());
        for (const auto& handler : pipeline_)
        {
            stats.handlerNames.push_back(handler->name());
        }
        return stats;
    }

private:
    void rebuildChain()
    {
        for (size_t i = 0; i + 1 < pipeline_.size(); ++i)
        {
            pipeline_[i]->setNext(pipeline_[i + 1]);
        }
        if (!pipeline_.empty())
        {
            pipeline_.back()->setNext(nullptr);
        }
    }

    std::vector<Strategy> pipeline_;
    SessionManagerType* sessionManager_{nullptr};
};

} // namespace snet::session