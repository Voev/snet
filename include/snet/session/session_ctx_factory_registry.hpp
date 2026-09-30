#pragma once

#include <cstddef>
#include <cstdio>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <snet/session/session_ctx_factory.hpp>

namespace snet::session
{

template <typename SessionManagerType>
class SessionCtxFactoryRegistry
{
public:
    using Session     = typename SessionManagerType::Session;
    using IFactory    = snet::session::ISessionCtxFactory<SessionManagerType>;
    using IFactoryPtr = std::shared_ptr<IFactory>;

    SessionCtxFactoryRegistry() = default;

    explicit SessionCtxFactoryRegistry(SessionManagerType* manager)
        : sessionManager_(manager)
    {
    }

    void setSessionManager(SessionManagerType* manager)
    {
        sessionManager_ = manager;
        for (auto& factory : factories_)
        {
            factory->setSessionManager(manager);
        }
    }

    SessionCtxFactoryRegistry& add(IFactoryPtr factory)
    {
        if (!factory)
        {
            return *this;
        }

        if (sessionManager_)
        {
            factory->setSessionManager(sessionManager_);
        }

        factories_.push_back(std::move(factory));
        return *this;
    }

    template <typename FactoryType, typename... Args>
    SessionCtxFactoryRegistry& addFactory(Args&&... args)
    {
        static_assert(std::is_base_of_v<IFactory, FactoryType>,
                      "FactoryType must derive from ISessionCtxFactory");

        auto factory = std::make_shared<FactoryType>(std::forward<Args>(args)...);
        return add(std::move(factory));
    }

    bool createContext(Session* session)
    {
        if (factories_.empty() || !session)
        {
            return false;
        }

        for (auto& factory : factories_)
        {
            if (!factory->createContext(session))
            {
                return false;
            }
        }
        return true;
    }

    bool destroyContext(Session* session)
    {
        if (factories_.empty() || !session)
        {
            return false;
        }

        bool success = true;
        for (auto it = factories_.rbegin(); it != factories_.rend(); ++it)
        {
            if (!(*it)->destroyContext(session))
            {
                success = false;
            }
        }
        return success;
    }

    void clear()
    {
        factories_.clear();
    }

    std::size_t size() const
    {
        return factories_.size();
    }

    bool empty() const
    {
        return factories_.empty();
    }

    template <typename T>
    T* findFactory()
    {
        static_assert(std::is_base_of_v<IFactory, T>,
                      "T must derive from ISessionCtxFactory");

        for (auto& factory : factories_)
        {
            if (auto* casted = dynamic_cast<T*>(factory.get()))
            {
                return casted;
            }
        }
        return nullptr;
    }

    IFactory* findFactory(const std::string& name)
    {
        for (auto& factory : factories_)
        {
            if (name == factory->name())
            {
                return factory.get();
            }
        }
        return nullptr;
    }

    bool insertFactory(std::size_t position, IFactoryPtr factory)
    {
        if (position > factories_.size() || !factory)
        {
            return false;
        }

        if (sessionManager_)
        {
            factory->setSessionManager(sessionManager_);
        }

        factories_.insert(
            factories_.begin() + static_cast<std::ptrdiff_t>(position),
            std::move(factory));
        return true;
    }

    bool removeFactory(const std::string& name)
    {
        for (auto it = factories_.begin(); it != factories_.end(); ++it)
        {
            if (name == (*it)->name())
            {
                factories_.erase(it);
                return true;
            }
        }
        return false;
    }

    void print(std::ostream& os) const
    {
        os << "Context factories: ";
        for (std::size_t i = 0; i < factories_.size(); ++i)
        {
            os << factories_[i]->name();
            if (i + 1 < factories_.size())
            {
                os << " -> ";
            }
        }
        os << "\n";
    }

private:
    std::vector<IFactoryPtr> factories_;
    SessionManagerType* sessionManager_{nullptr};
};

} // namespace snet::session