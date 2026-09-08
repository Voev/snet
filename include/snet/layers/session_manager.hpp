#pragma once

#include <atomic>
#include <chrono>
#include <cstring>
#include <type_traits>
#include <utility>
#include <algorithm>
#include <cstdlib>

#include <snet/layers/session_ctx_container.hpp>
#include <snet/layers/session_ctx_pool_manager.hpp>
#include <casket/types/flat_hash_table.hpp>

namespace snet::layers
{

static constexpr size_t CACHE_LINE_SIZE = 64;

template <typename KeyType, typename ContextContainer, typename Hash = std::hash<KeyType>,
          typename KeyEqual = std::equal_to<KeyType>>
class SessionManager
{
public:
    using Key = KeyType;
    using Container = ContextContainer;
    using Session = typename casket::FlatHashMap<Key, Container, Hash, KeyEqual>::value_type;

    struct Config
    {
        size_t max_sessions{1000000};
        uint32_t session_timeout_sec{300};
        uint32_t cleanup_interval_sec{5};
        float load_factor{0.75f};
        size_t removal_queue_size{1024}; // Фиксированный размер очереди удаления
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
        , session_counter_(other.session_counter_.load())
    {
    }

    // ========================================================================
    // Основной API
    // ========================================================================

    template <typename... ContextArgs>
    Session* getOrCreate(const Key& key, ContextArgs&&... ctx_args)
    {
        // Обрабатываем очередь удаления
        processRemovalQueue();

        auto* session = findSession(key);
        if (session)
        {
            updateSession(session);
            return session;
        }
        return createSession(key, std::forward<ContextArgs>(ctx_args)...);
    }

    Session* find(const Key& key)
    {
        processRemovalQueue();
        return findSession(key);
    }

    const Session* find(const Key& key) const
    {
        return findSession(key);
    }

    // ========================================================================
    // Контексты
    // ========================================================================

    template <typename ContextType>
    ContextType* createAndAddContext(Session* session, uint32_t flags = 0, size_t index = 0)
    {
        if (!session)
            return nullptr;

        auto* ctx = context_pools_.template allocate<ContextType>();
        if (!ctx)
            return nullptr;

        if (!session->contexts.template set<ContextType>(ctx, index, flags))
        {
            context_pools_.template deallocate<ContextType>(ctx);
            return nullptr;
        }

        return ctx;
    }

    template <typename ContextType>
    ContextType* getContext(Session* session, size_t index = 0)
    {
        if (!session)
            return nullptr;
        return session->contexts.template get<ContextType>(index);
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
        {
            return false;
        }

        context_pools_.template deallocate<ContextType>(ctx);
        return true;
    }

    template <typename ContextType>
    bool hasContext(Session* session, size_t index = 0)
    {
        if (!session)
            return false;
        return session->contexts.template has<ContextType>(index);
    }

    // ========================================================================
    // Управление сессиями
    // ========================================================================

    bool removeSession(const Key& key)
    {
        // Добавляем в очередь на удаление (не удаляем сразу!)
        return addToRemovalQueue(key);
    }

    size_t cleanup()
    {
        // Обрабатываем очередь удаления
        return processRemovalQueue();
    }

    // ========================================================================
    // Доступ к конфигурации
    // ========================================================================

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
        return removal_queue_.size();
    }
    size_t getRemovalQueuePending() const
    {
        return removal_queue_.size() - removal_queue_.available();
    }

    // ========================================================================
    // Итерация по сессиям
    // ========================================================================

    template <typename Func>
    void forEachSession(Func&& func)
    {
        processRemovalQueue();
        for (auto& entry : session_map_)
        {
            func(&entry.value);
        }
    }

    template <typename Func>
    void forEachSession(Func&& func) const
    {
        for (const auto& entry : session_map_)
        {
            func(&entry.value);
        }
    }

private:
    // ========================================================================
    // Фиксированная очередь с вытеснением (кольцевой буфер)
    // ========================================================================

    class RemovalQueue
    {
    public:
        explicit RemovalQueue(size_t capacity)
            : capacity_(capacity)
            , buffer_(static_cast<Key*>(alignedAlloc(sizeof(Key) * capacity, CACHE_LINE_SIZE)))
            , head_(0)
            , tail_(0)
            , count_(0)
        {
        }

        ~RemovalQueue()
        {
            if (buffer_)
            {
                free(buffer_);
            }
        }

        // Добавление с вытеснением
        bool push(const Key& key)
        {
            // Если очередь полна - вытесняем самый старый
            if (count_ >= capacity_)
            {
                // Вытесняем: просто перезаписываем tail
                // Старый элемент будет удалён при следующей обработке
                buffer_[tail_] = key;
                tail_ = (tail_ + 1) % capacity_;
                // head не меняем, но count остаётся полным
                return true;
            }

            buffer_[tail_] = key;
            tail_ = (tail_ + 1) % capacity_;
            count_++;
            return true;
        }

        // Извлечение из очереди
        bool pop(Key& key)
        {
            if (count_ == 0)
                return false;

            key = buffer_[head_];
            head_ = (head_ + 1) % capacity_;
            count_--;
            return true;
        }

        size_t size() const
        {
            return capacity_;
        }
        size_t available() const
        {
            return capacity_ - count_;
        }
        bool empty() const
        {
            return count_ == 0;
        }
        bool full() const
        {
            return count_ == capacity_;
        }
        size_t pending() const
        {
            return count_;
        }

        void clear()
        {
            head_ = 0;
            tail_ = 0;
            count_ = 0;
        }

    private:
        size_t capacity_;
        Key* buffer_;
        size_t head_;
        size_t tail_;
        size_t count_;

        static void* alignedAlloc(size_t size, size_t alignment)
        {
            void* ptr = nullptr;
            if (posix_memalign(&ptr, alignment, size) != 0)
            {
                return nullptr;
            }
            return ptr;
        }
    };

    // ========================================================================
    // Внутренняя структура сессии
    // ========================================================================

    struct Session
    {
        Key key;
        Container contexts;
        uint32_t flags;
        uint64_t created_at;
        uint64_t last_activity;
        uint64_t timeout_at;
    };

    // ========================================================================
    // Поля класса
    // ========================================================================

    Config config_;

    casket::FlatHashMap<Key, Session, Hash, KeyEqual> session_map_;
    RemovalQueue removal_queue_;

    typename Container::PoolManagerType context_pools_;
    std::atomic<uint64_t> session_counter_{0};

    uint64_t last_cleanup_time_{0};

    // ========================================================================
    // Управление сессиями
    // ========================================================================

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

    // Обработка очереди удаления
    size_t processRemovalQueue()
    {
        size_t processed = 0;
        Key key;

        // Обрабатываем все элементы в очереди
        while (removal_queue_.pop(key))
        {
            auto* session = findSession(key);
            if (session)
            {
                // Освобождаем контексты
                if (session->contexts.activeCount() > 0)
                {
                    session->contexts.forEach(
                        [this](uint32_t type_id, void* data)
                        {
                            (tryDeallocateContext<ContextTypes>(type_id, data), ...);
                        });
                    session->contexts.clearAll();
                }

                // Удаляем из хэш-таблицы
                session_map_.erase(key);
                processed++;
            }
        }

        return processed;
    }

    template <typename... ContextArgs>
    Session* createSession(const Key& key, ContextArgs&&... ctx_args)
    {
        // Проверяем лимит
        if (session_map_.size() >= config_.max_sessions)
        {
            // Пытаемся освободить место через очередь
            processRemovalQueue();

            if (session_map_.size() >= config_.max_sessions)
            {
                // Если всё ещё нет места - вытесняем самую старую сессию
                evictOldestSession();
            }
        }

        // Проверяем capacity хэш-таблицы
        if (session_map_.size() >= session_map_.capacity() * 0.85)
        {
            session_map_.reserve(session_map_.capacity() * 2);
        }

        Session session;
        session.key = key;
        session.flags = 0;
        session.created_at = getCurrentTimestamp();
        session.last_activity = session.created_at;
        session.timeout_at = session.created_at + config_.session_timeout_sec * 1000000ULL;
        session.contexts = Container();

        initializeContexts(&session, std::forward<ContextArgs>(ctx_args)...);

        auto [it, inserted] = session_map_.insert(key, std::move(session));
        if (!inserted)
        {
            return nullptr;
        }

        session_counter_++;
        return &it->value;
    }

    void evictOldestSession()
    {
        if (session_map_.empty())
            return;

        // Находим самую старую сессию
        Session* oldest = nullptr;
        uint64_t oldest_time = UINT64_MAX;

        for (auto& entry : session_map_)
        {
            auto& session = entry.value;
            if (session.last_activity < oldest_time)
            {
                oldest_time = session.last_activity;
                oldest = &session;
            }
        }

        if (oldest)
        {
            // Добавляем в очередь на удаление
            removal_queue_.push(oldest->key);
            // Немедленно обрабатываем
            processRemovalQueue();
        }
    }

    template <typename... ContextArgs>
    void initializeContexts(Session* session, ContextArgs&&... ctx_args)
    {
        (initializeContext<ContextArgs>(session, std::forward<ContextArgs>(ctx_args)), ...);
    }

    template <typename ContextType>
    void initializeContext(Session* session, ContextType* ctx)
    {
        if (ctx)
        {
            session->contexts.template set<ContextType>(ctx);
        }
    }

    void updateSession(Session* session)
    {
        session->last_activity = getCurrentTimestamp();
    }

    void cleanupAllSessions()
    {
        // Обрабатываем очередь удаления
        processRemovalQueue();

        if (session_map_.empty())
            return;

        // Освобождаем все контексты
        for (auto& entry : session_map_)
        {
            auto& session = entry.value;
            if (session.contexts.activeCount() > 0)
            {
                session.contexts.forEach(
                    [this](uint32_t type_id, void* data)
                    {
                        (tryDeallocateContext<ContextTypes>(type_id, data), ...);
                    });
                session.contexts.clearAll();
            }
        }

        session_map_.clear();
        removal_queue_.clear();
    }

    template <typename ContextType>
    void tryDeallocateContext(uint32_t type_id, void* data)
    {
        if (type_id == ContextType::CONTEXT_ID)
        {
            context_pools_.template deallocate<ContextType>(static_cast<ContextType*>(data));
        }
    }

    static uint64_t getCurrentTimestamp()
    {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    }
};

} // namespace snet::layers