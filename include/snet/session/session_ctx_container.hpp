#pragma once

#include <algorithm>
#include <cstdint>
#include <type_traits>
#include <typeinfo>
#include <chrono>
#include <cstring>

namespace snet::session
{

namespace detail
{

constexpr uint32_t compileTimeHash(const char* str, uint32_t hash = 0)
{
    return *str ? compileTimeHash(str + 1, (hash << 5) - hash + *str) : hash;
}

template <typename T>
constexpr uint32_t getTypeId()
{
    constexpr const char* name = __PRETTY_FUNCTION__;
    constexpr uint32_t id = compileTimeHash(name);
    return id;
}

} // namespace detail

template <typename... ContextTypes>
class SessionCtxContainer
{
public:
    static constexpr size_t CONTEXT_COUNT = sizeof...(ContextTypes);

    static_assert(CONTEXT_COUNT > 0, "At least one context type must be specified");

    static constexpr size_t MAX_INSTANCES = std::max({ContextTypes::MAX_INSTANCES...});

    struct ContextSlot
    {
        uint32_t typeId{0};
        uint32_t instanceId{0};
        void* data{nullptr};
    };

    SessionCtxContainer()
    {
        for (size_t i = 0; i < CONTEXT_COUNT * MAX_INSTANCES; ++i)
        {
            slots[i] = ContextSlot{};
        }
    }

    template <typename ContextType>
    ContextType* get(size_t index = 0)
    {
        static_assert(CONTEXT_COUNT > 0, "No context types defined");

        if (index >= ContextType::MAX_INSTANCES)
        {
            return nullptr;
        }

        constexpr size_t typeIndex = getTypeIndex<ContextType>();
        size_t slotIndex = typeIndex * MAX_INSTANCES + index;

        if (slotIndex >= CONTEXT_COUNT * MAX_INSTANCES)
        {
            return nullptr;
        }

        auto& slot = slots[slotIndex];
        if (slot.data)
        {
            return static_cast<ContextType*>(slot.data);
        }
        return nullptr;
    }

    template <typename ContextType>
    bool set(ContextType* data, size_t index = 0)
    {
        if (!data || index >= ContextType::MAX_INSTANCES)
        {
            return false;
        }

        constexpr size_t typeIndex = getTypeIndex<ContextType>();
        size_t slotIndex = typeIndex * MAX_INSTANCES + index;

        if (slotIndex >= CONTEXT_COUNT * MAX_INSTANCES)
        {
            return false;
        }

        auto& slot = slots[slotIndex];

        if (slot.data && slot.data != data)
        {
            if constexpr (std::is_destructible_v<ContextType>)
            {
                static_cast<ContextType*>(slot.data)->~ContextType();
            }
            activeCount_--;
            slotMask_ &= ~(1u << slotIndex);
        }

        slot.typeId = detail::getTypeId<ContextType>();
        slot.instanceId = static_cast<uint32_t>(index);
        slot.data = data;

        if (!(slotMask_ & (1u << slotIndex)))
        {
            activeCount_++;
        }
        slotMask_ |= (1u << slotIndex);

        return true;
    }

    template <typename ContextType>
    bool clear(size_t index = 0)
    {
        if (index >= ContextType::MAX_INSTANCES)
        {
            return false;
        }

        constexpr size_t typeIndex = getTypeIndex<ContextType>();
        size_t slotIndex = typeIndex * MAX_INSTANCES + index;

        if (slotIndex >= CONTEXT_COUNT * MAX_INSTANCES)
        {
            return false;
        }

        auto& slot = slots[slotIndex];
        if (slot.data)
        {
            if constexpr (std::is_destructible_v<ContextType>)
            {
                static_cast<ContextType*>(slot.data)->~ContextType();
            }
            slot.data = nullptr;
            slot.typeId = 0;
            slotMask_ &= ~(1u << slotIndex);
            activeCount_--;
            return true;
        }
        return false;
    }

    template <typename ContextType>
    bool has(size_t index = 0) const
    {
        if (index >= ContextType::MAX_INSTANCES)
        {
            return false;
        }

        constexpr size_t typeIndex = getTypeIndex<ContextType>();
        size_t slotIndex = typeIndex * MAX_INSTANCES + index;

        if (slotIndex >= CONTEXT_COUNT * MAX_INSTANCES)
        {
            return false;
        }

        const auto& slot = slots[slotIndex];
        return (slotMask_ & (1u << slotIndex)) != 0 && slot.data != nullptr;
    }

    void clearAll()
    {
        for (size_t i = 0; i < CONTEXT_COUNT * MAX_INSTANCES; ++i)
        {
            if (slots[i].data)
            {
                slots[i].data = nullptr;
                slots[i].typeId = 0;
            }
        }
        activeCount_ = 0;
        slotMask_ = 0;
    }

    template <typename Func>
    void forEach(Func&& func)
    {
        for (size_t i = 0; i < CONTEXT_COUNT * MAX_INSTANCES; ++i)
        {
            if (slots[i].data)
            {
                func(slots[i].typeId, slots[i].data);
            }
        }
    }

    size_t activeCount() const
    {
        return activeCount_;
    }

    bool empty() const
    {
        return activeCount_ == 0;
    }

    uint32_t slotMask() const
    {
        return slotMask_;
    }

    template <typename T>
    static constexpr uint32_t getTypeId()
    {
        return detail::getTypeId<T>();
    }

private:
    ContextSlot slots[CONTEXT_COUNT * MAX_INSTANCES];
    uint32_t activeCount_{0};
    uint32_t slotMask_{0};

    template <typename T, size_t I = 0, typename... Args>
    struct TypeIndexImpl;

    template <typename T, size_t I, typename First, typename... Rest>
    struct TypeIndexImpl<T, I, First, Rest...>
    {
        static constexpr size_t value = std::is_same_v<T, First> ? I : TypeIndexImpl<T, I + 1, Rest...>::value;
    };

    template <typename T, size_t I>
    struct TypeIndexImpl<T, I>
    {
        static constexpr size_t value = sizeof...(ContextTypes);
    };

    template <typename T>
    static constexpr size_t getTypeIndex()
    {
        constexpr size_t idx = TypeIndexImpl<T, 0, ContextTypes...>::value;
        static_assert(idx < sizeof...(ContextTypes), "Context type not found in the list");
        return idx;
    }
};

} // namespace snet::session