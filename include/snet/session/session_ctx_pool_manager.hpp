#pragma once
#include <tuple>
#include <casket/types/fixed_object_pool.hpp>

namespace snet::session
{

namespace detail
{
template <typename T, typename... Ts>
struct TypeIndex;

template <typename T, typename... Rest>
struct TypeIndex<T, T, Rest...>
{
    static constexpr std::size_t value = 0;
};

template <typename T, typename U, typename... Rest>
struct TypeIndex<T, U, Rest...>
{
    static constexpr std::size_t value = 1 + TypeIndex<T, Rest...>::value;
};

template <typename T, typename... Ts>
inline constexpr std::size_t type_index_v = TypeIndex<T, Ts...>::value;

} // namespace detail

template <typename ContextType>
struct PoolTraits
{
    static constexpr size_t pool_size = 8192;
};

template <typename... ContextTypes>
class SessionCtxPoolManager
{
public:
    SessionCtxPoolManager()
        : pools_(createPools())
    {
    }

    template <typename... Sizes>
    explicit SessionCtxPoolManager(Sizes... sizes)
        : pools_(createPools(sizes...))
    {
        static_assert(sizeof...(Sizes) == 0 || sizeof...(Sizes) == sizeof...(ContextTypes),
                      "Number of sizes must match number of context types");
    }

    template <typename ContextType>
    ContextType* allocate()
    {
        return getPool<ContextType>().acquire();
    }

    template <typename ContextType, typename... Args>
    ContextType* allocate(Args&&... args)
    {
        return getPool<ContextType>().acquire(std::forward<Args>(args)...);
    }

    template <typename ContextType>
    void deallocate(ContextType* ctx)
    {
        getPool<ContextType>().release(ctx);
    }

    template <typename ContextType>
    size_t capacity() const
    {
        return getPool<ContextType>().capacity();
    }

    void printStats() const
    {
        printf("=== Context Pools Stats ===\n");
        (printPoolStats<ContextTypes>(), ...);
    }

    void resetAll()
    {
        (getPool<ContextTypes>().reset(), ...);
    }

private:
    std::tuple<casket::FixedObjectPool<ContextTypes>...> pools_;

    template <typename ContextType>
    casket::FixedObjectPool<ContextType>& getPool()
    {
        return std::get<detail::type_index_v<ContextType, ContextTypes...>>(pools_);
    }

    template <typename ContextType>
    const casket::FixedObjectPool<ContextType>& getPool() const
    {
        return std::get<detail::type_index_v<ContextType, ContextTypes...>>(pools_);
    }

    static auto createPools()
    {
        return std::tuple<casket::FixedObjectPool<ContextTypes>...>(
            casket::FixedObjectPool<ContextTypes>(PoolTraits<ContextTypes>::pool_size)...);
    }

    template <typename... Sizes>
    static auto createPools(Sizes... sizes)
    {
        return std::tuple<casket::FixedObjectPool<ContextTypes>...>(casket::FixedObjectPool<ContextTypes>(sizes)...);
    }

    template <typename ContextType>
    void printPoolStats() const
    {
        const auto& pool = getPool<ContextType>();
        printf("  %s: capacity=%zu\n", typeid(ContextType).name(), pool.capacity());
    }
};

} // namespace snet::session