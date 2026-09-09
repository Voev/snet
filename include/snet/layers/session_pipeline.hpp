#pragma once
#include <vector>
#include <memory>
#include <cstdio>
#include <snet/layers/session_handler.hpp>

namespace snet::layers
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
            return *this;

        if (sessionManager_)
        {
            strategy->setSessionManager(sessionManager_);
        }

        if (pipeline_.empty())
        {
            pipeline_.push_back(std::move(strategy));
        }
        else
        {
            pipeline_.back()->setNext(strategy);
            pipeline_.push_back(std::move(strategy));
        }
        return *this;
    }

    template <typename HandlerType, typename... Args>
    SessionPipeline& addHandler(Args&&... args)
    {
        static_assert(std::is_base_of_v<Handler, HandlerType>, "HandlerType must derive from ISessionHandler");

        auto handler = std::make_shared<HandlerType>(std::forward<Args>(args)...);
        return add(handler);
    }

    // ========== Создание контекста для всей цепочки ==========
    bool createContext(Session* session)
    {
        if (pipeline_.empty() || !session)
        {
            return false;
        }

        bool success = true;
        for (auto& handler : pipeline_)
        {
            if (!handler->createContext(session))
            {
                success = false;
                break;
            }
        }

        return success;
    }

    // ========== Уничтожение контекста для всей цепочки ==========
    bool destroyContext(Session* session)
    {
        if (pipeline_.empty() || !session)
        {
            return false;
        }

        bool success = true;
        // Проходим в обратном порядке
        for (auto it = pipeline_.rbegin(); it != pipeline_.rend(); ++it)
        {
            if (!(*it)->destroyContext(session))
            {
                success = false;
            }
        }

        return success;
    }

    // ========== Обработка пакета ==========
    PacketStatus processPacket(Session* session, layers::Packet* packet)
    {
        if (pipeline_.empty() || !session || !packet)
        {
            return PacketStatus::Error_NoMemory;
        }

        return pipeline_[0]->processPacket(session, packet);
    }

    // ========== Управление ==========
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
        return pipeline_.empty() ? nullptr : pipeline_[0];
    }

    Strategy getLast() const
    {
        return pipeline_.empty() ? nullptr : pipeline_.back();
    }

    template <typename T>
    T* findHandler()
    {
        static_assert(std::is_base_of_v<Handler, T>, "T must derive from ISessionHandler");

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
            return false;

        if (sessionManager_)
        {
            strategy->setSessionManager(sessionManager_);
        }

        if (position == 0)
        {
            if (!pipeline_.empty())
            {
                strategy->setNext(pipeline_[0]);
            }
            pipeline_.insert(pipeline_.begin(), std::move(strategy));
        }
        else
        {
            auto it = pipeline_.begin() + position - 1;
            strategy->setNext((*it)->getNext());
            (*it)->setNext(strategy);
            pipeline_.insert(it + 1, std::move(strategy));
        }

        return true;
    }

    bool removeHandler(const std::string& name)
    {
        for (size_t i = 0; i < pipeline_.size(); ++i)
        {
            if (pipeline_[i]->name() == name)
            {
                if (i == 0)
                {
                    if (pipeline_.size() > 1)
                    {
                        pipeline_.erase(pipeline_.begin());
                    }
                    else
                    {
                        pipeline_.clear();
                    }
                }
                else if (i == pipeline_.size() - 1)
                {
                    pipeline_.pop_back();
                    if (!pipeline_.empty())
                    {
                        pipeline_.back()->setNext(nullptr);
                    }
                }
                else
                {
                    pipeline_[i - 1]->setNext(pipeline_[i + 1]);
                    pipeline_.erase(pipeline_.begin() + i);
                }
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
        for (const auto& handler : pipeline_)
        {
            stats.handlerNames.push_back(handler->name());
        }
        return stats;
    }

private:
    std::vector<Strategy> pipeline_;
    SessionManagerType* sessionManager_{nullptr};
};

} // namespace snet::layers