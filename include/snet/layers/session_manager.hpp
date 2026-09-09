#pragma once

#include <chrono>
#include <type_traits>
#include <utility>
#include <algorithm>
#include <tuple>

#include <snet/layers/session_ctx_container.hpp>
#include <snet/layers/session_ctx_pool_manager.hpp>
#include <snet/layers/session_pipeline.hpp>

#include <snet/layers/checksums.hpp>

#include <casket/types/flat_hash_table.hpp>
#include <casket/types/ring_buffer.hpp>

namespace snet::layers
{

template <typename Tuple>
struct SessionCtxContainerFromTuple;

template <typename... Types>
struct SessionCtxContainerFromTuple<std::tuple<Types...>>
{
    using type = SessionCtxContainer<Types...>;
};

template <typename Tuple>
struct SessionCtxPoolManagerFromTuple;

template <typename... Types>
struct SessionCtxPoolManagerFromTuple<std::tuple<Types...>>
{
    using type = SessionCtxPoolManager<Types...>;
};

template <typename KeyType, typename ContextTypesTuple, typename Hash = std::hash<KeyType>,
          typename KeyEqual = std::equal_to<KeyType>>
class SessionManager
{
public:
    using Key = KeyType;
    using Pipeline = SessionPipeline<SessionManager<KeyType, ContextTypesTuple, Hash, KeyEqual>>;
    using ContextContainer = typename SessionCtxContainerFromTuple<ContextTypesTuple>::type;
    using PoolManager = typename SessionCtxPoolManagerFromTuple<ContextTypesTuple>::type;

    struct Session
    {
        Key key;
        ContextContainer contexts;
        uint64_t created_at{0};
        uint64_t last_activity{0};
        uint64_t timeout_at{0};
        uint32_t flags{0};
    };

    struct Config
    {
        size_t max_sessions{1000};
        uint32_t session_timeout_sec{300};
        uint32_t cleanup_interval_sec{5};
        float load_factor{0.75f};
        size_t removal_queue_size{1024};
    };

    explicit SessionManager(const Config& config = Config{})
        : config_(config)
        , session_map_(config.max_sessions, config.load_factor)
        , removal_queue_(config.removal_queue_size)
    {
    }

    ~SessionManager()
    {
        cleanupAllSessions();
    }

    SessionManager(const SessionManager&) = delete;
    SessionManager& operator=(const SessionManager&) = delete;

    SessionManager(SessionManager&& other) noexcept
        : config_(std::move(other.config_))
        , session_map_(std::move(other.session_map_))
        , removal_queue_(std::move(other.removal_queue_))
        , session_counter_(other.session_counter_)
        , context_pools_(std::move(other.context_pools_))
    {
    }

    void setPipeline(std::unique_ptr<Pipeline> pipeline)
    {
        pipeline_ = std::move(pipeline);
        if (pipeline_)
        {
            pipeline_->setSessionManager(this);
        }
    }

    PacketStatus processPacket(Packet* packet)
    {
        if (!packet)
        {
            return PacketStatus::Error_NoMemory;
        }

        IPAddress srcIP, dstIP;
        auto ipHeader = packet->getHeader<IPv4Header>(IPv4);
        if (ipHeader.isValid())
        {
            srcIP = IPAddress(ipHeader.srcAddr());
            dstIP = IPAddress(ipHeader.dstAddr());
        }
        else
        {
            return PacketStatus::NonIpPacket;
        }

        const auto* layer = packet->findLayer(TCP);
        if (!layer)
        {
            return PacketStatus::NonTcpPacket;
        }
        auto tcpHeader = packet->getHeader<TCPHeader>(*layer);

        uint32_t flowKey =
            layers::hash5Tuple(srcIP, dstIP, tcpHeader.srcPort(), tcpHeader.dstPort(), ipHeader.protocol(), false);

        auto* session = findSession(flowKey);
        bool isNewSession = false;

        if (!session)
        {
            session = newSession(flowKey);
            if (!session)
            {
                return PacketStatus::Error_NoMemory;
            }
            isNewSession = true;
        }

        updateSession(session);

        if (pipeline_)
        {
            if (isNewSession)
            {
                pipeline_->createContext(session);
            }
            return pipeline_->processPacket(session, packet);
        }

        return PacketStatus::TcpMessageHandled;
    }

    template <typename ContextType>
    Session* getOrCreate(const Key& key, ContextType* ctx)
    {
        processRemovalQueue();

        auto* session = findSession(key);
        if (session)
        {
            updateSession(session);
            return session;
        }
        return createSession(key, ctx);
    }

    template <typename... ContextTypes>
    Session* getOrCreate(const Key& key, ContextTypes*... ctxs)
    {
        processRemovalQueue();

        auto* session = findSession(key);
        if (session)
        {
            updateSession(session);
            return session;
        }
        return createSession(key, ctxs...);
    }

    Session* find(const Key& key)
    {
        return findSession(key);
    }

    const Session* find(const Key& key) const
    {
        return findSession(key);
    }

    template <typename ContextType>
    ContextType* allocateContext()
    {
        return context_pools_.template allocate<ContextType>();
    }

    template <typename ContextType, typename... Args>
    ContextType* allocateContext(Args&&... args)
    {
        return context_pools_.template allocate<ContextType>(std::forward<Args>(args)...);
    }

    template <typename ContextType>
    void deallocateContext(ContextType* ctx)
    {
        context_pools_.template deallocate<ContextType>(ctx);
    }

    template <typename ContextType>
    ContextType* getContext(Session* session, size_t index = 0)
    {
        if (!session)
            return nullptr;
        return session->contexts.template get<ContextType>(index);
    }

    template <typename ContextType>
    bool setContext(Session* session, ContextType* ctx, size_t index = 0)
    {
        if (!session || !ctx)
            return false;
        return session->contexts.template set<ContextType>(ctx, index);
    }

    template <typename ContextType>
    bool removeContext(Session* session, size_t index = 0)
    {
        if (!session)
            return false;

        auto* ctx = session->contexts.template get<ContextType>(index);
        if (!ctx)
            return false;

        if (!session->contexts.template clear<ContextType>(index))
            return false;

        context_pools_.template deallocate<ContextType>(ctx);
        return true;
    }

    template <typename ContextType>
    bool hasContext(const Session* session, size_t index = 0) const
    {
        if (!session)
            return false;
        return session->contexts.template has<ContextType>(index);
    }

    PoolManager& getPoolManager()
    {
        return context_pools_;
    }

    const PoolManager& getPoolManager() const
    {
        return context_pools_;
    }

    bool removeSession(const Key& key)
    {
        return addToRemovalQueue(key);
    }

    size_t cleanup()
    {
        return processRemovalQueue();
    }

    const Config& getConfig() const
    {
        return config_;
    }

    size_t getActiveSessions() const
    {
        return session_map_.size();
    }

    size_t getMaxSessions() const
    {
        return config_.max_sessions;
    }

    size_t getRemovalQueueSize() const
    {
        return removal_queue_.capacity();
    }

    size_t getRemovalQueuePending() const
    {
        return removal_queue_.size();
    }

    bool isRemovalQueueFull() const
    {
        return removal_queue_.full();
    }

    uint64_t getSessionCounter() const
    {
        return session_counter_;
    }

    template <typename Func>
    void forEachSession(Func&& func)
    {
        auto it = session_map_.begin();
        auto end = session_map_.end();
        for (; it != end; ++it)
        {
            func(&(*it).second);
        }
    }

    template <typename Func>
    void forEachSession(Func&& func) const
    {
        auto it = session_map_.begin();
        auto end = session_map_.end();
        for (; it != end; ++it)
        {
            func(&(*it).second);
        }
    }

    void resetAllPools()
    {
        context_pools_.resetAll();
    }

    void printPoolStats() const
    {
        context_pools_.printStats();
    }

private:
    Config config_;
    casket::FlatHashMap<Key, Session, casket::LinearProbing, Hash, KeyEqual> session_map_;
    casket::RingBuffer<Key> removal_queue_;
    PoolManager context_pools_;
    std::unique_ptr<Pipeline> pipeline_;
    uint64_t session_counter_{0};

    Session* findSession(const Key& key)
    {
        return session_map_.find(key);
    }

    const Session* findSession(const Key& key) const
    {
        return session_map_.find(key);
    }

    bool addToRemovalQueue(const Key& key)
    {
        return removal_queue_.push(key);
    }

    size_t processRemovalQueue()
    {
        size_t processed = 0;
        Key key;

        while (removal_queue_.pop(key))
        {
            auto* session = session_map_.find(key);
            if (session)
            {
                if (pipeline_)
                {
                    pipeline_->destroyContext(session);
                }
                session->contexts.clearAll();
                session_map_.erase(key);
                processed++;
            }
        }

        return processed;
    }

    template <typename ContextType>
    Session* createSession(const Key& key, ContextType* ctx)
    {
        if (session_map_.size() >= config_.max_sessions)
        {
            processRemovalQueue();

            if (session_map_.size() >= config_.max_sessions)
            {
                evictOldestSession();
            }
        }

        if (session_map_.size() >= session_map_.capacity() * 0.85f)
        {
            session_map_.reserve(session_map_.capacity() * 2);
        }

        Session session;
        session.key = key;
        session.flags = 0;
        session.created_at = getCurrentTimestamp();
        session.last_activity = session.created_at;
        session.timeout_at = session.created_at + static_cast<uint64_t>(config_.session_timeout_sec) * 1000000ULL;
        session.contexts = ContextContainer();

        if (ctx)
        {
            session.contexts.template set<ContextType>(ctx);
        }

        if (!session_map_.insert(key, std::move(session)))
        {
            if (ctx)
            {
                context_pools_.template deallocate<ContextType>(ctx);
            }
            return nullptr;
        }

        session_counter_++;
        return session_map_.find(key);
    }

    Session* newSession(const Key& key)
    {
        if (session_map_.size() >= config_.max_sessions)
        {
            processRemovalQueue();

            if (session_map_.size() >= config_.max_sessions)
            {
                evictOldestSession();
            }
        }

        if (session_map_.size() >= session_map_.capacity() * 0.85f)
        {
            session_map_.reserve(session_map_.capacity() * 2);
        }

        Session session;
        session.key = key;
        session.flags = 0;
        session.created_at = getCurrentTimestamp();
        session.last_activity = session.created_at;
        session.timeout_at = session.created_at + static_cast<uint64_t>(config_.session_timeout_sec) * 1000000ULL;
        session.contexts = ContextContainer();

        if (!session_map_.insert(key, std::move(session)))
        {
            return nullptr;
        }

        session_counter_++;
        return session_map_.find(key);
    }

    template <typename... ContextTypes>
    Session* createSession(const Key& key, ContextTypes*... ctxs)
    {
        if (session_map_.size() >= config_.max_sessions)
        {
            processRemovalQueue();

            if (session_map_.size() >= config_.max_sessions)
            {
                evictOldestSession();
            }
        }

        if (session_map_.size() >= session_map_.capacity() * 0.85f)
        {
            session_map_.reserve(session_map_.capacity() * 2);
        }

        Session session;
        session.key = key;
        session.flags = 0;
        session.created_at = getCurrentTimestamp();
        session.last_activity = session.created_at;
        session.timeout_at = session.created_at + static_cast<uint64_t>(config_.session_timeout_sec) * 1000000ULL;
        session.contexts = ContextContainer();

        (initializeContext(&session, ctxs), ...);

        if (!session_map_.insert(key, std::move(session)))
        {
            (context_pools_.template deallocate<ContextTypes>(ctxs), ...);
            return nullptr;
        }

        session_counter_++;
        return session_map_.find(key);
    }

    bool destroySession(Session* session)
    {
        if (!session)
            return false;

        if (pipeline_)
        {
            pipeline_->destroyContext(session);
        }

        // Очищаем контексты
        session->contexts.clearAll();

        return addToRemovalQueue(session->key);
    }

    void evictOldestSession()
    {
        if (session_map_.empty())
            return;

        Session* oldest = nullptr;
        uint64_t oldest_time = UINT64_MAX;

        auto it = session_map_.begin();
        auto end = session_map_.end();
        for (; it != end; ++it)
        {
            auto& session = (*it).second;
            if (session.last_activity < oldest_time)
            {
                oldest_time = session.last_activity;
                oldest = &session;
            }
        }

        if (oldest)
        {
            removal_queue_.push(oldest->key);
            processRemovalQueue();
        }
    }

    template <typename ContextType>
    void initializeContext(Session* session, ContextType* ctx)
    {
        if (ctx && session)
        {
            session->contexts.template set<ContextType>(ctx);
        }
    }

    void updateSession(Session* session)
    {
        if (session)
        {
            session->last_activity = getCurrentTimestamp();
        }
    }

    void cleanupAllSessions()
    {
        processRemovalQueue();

        auto it = session_map_.begin();
        auto end = session_map_.end();
        for (; it != end; ++it)
        {
            auto* session = &(*it).second;
            if (pipeline_)
            {
                pipeline_->destroyContext(session);
            }
            session->contexts.clearAll();
        }

        session_map_.clear();
        removal_queue_.clear();
        context_pools_.resetAll();
    }

    static uint64_t getCurrentTimestamp()
    {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    }
};

} // namespace snet::layers