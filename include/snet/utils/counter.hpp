#pragma once
#include <cstdint>
#include <limits>
#include <type_traits>

namespace snet
{

/// @brief Generic counter with automatic rollover handling.
/// @tparam T Underlying counter type (must be unsigned).
/// @tparam AccumulatorT Accumulator type for rollover tracking (must be larger than T).
template <typename T, typename AccumulatorT = uint64_t>
class Counter
{
    static_assert(std::is_unsigned_v<T>, "T must be unsigned integer type");
    static_assert(std::is_unsigned_v<AccumulatorT>, "AccumulatorT must be unsigned integer type");
    static_assert(sizeof(AccumulatorT) > sizeof(T), "AccumulatorT must be larger than T");

public:
    /// @brief Default constructor.
    Counter() = default;

    /// @brief Constructor with base value.
    /// @param[in] baseValue Initial counter value.
    explicit Counter(T baseValue)
        : base_(baseValue)
        , lastValue_(baseValue)
    {
    }

    /// @brief Updates counter with new value, handling rollover.
    /// @param[in] newValue New counter value.
    void update(T newValue)
    {
        if (newValue < lastValue_)
        {
            rollover_ += static_cast<AccumulatorT>(std::numeric_limits<T>::max()) + 1;
        }
        lastValue_ = newValue;
    }

    /// @brief Adds direct increment to accumulator.
    /// @param[in] increment Value to add.
    void add(AccumulatorT increment)
    {
        directValue_ += increment;
    }

    /// @brief Gets total accumulated value.
    /// @return Total counter value including rollovers and direct additions.
    AccumulatorT get() const
    {
        return rollover_ + static_cast<AccumulatorT>(lastValue_) + directValue_;
    }

    /// @brief Gets value relative to base.
    /// @return Total value minus base.
    AccumulatorT getRelative() const
    {
        return rollover_ + static_cast<AccumulatorT>(lastValue_) + directValue_ - base_;
    }

    /// @brief Resets counter to base value.
    /// @param[in] baseValue New base value (default 0).
    void reset(T baseValue = 0)
    {
        base_ = static_cast<AccumulatorT>(baseValue);
        lastValue_ = baseValue;
        rollover_ = 0;
        directValue_ = 0;
    }

    /// @brief Sets base value without resetting counter.
    /// @param[in] baseValue New base value.
    void setBase(T baseValue)
    {
        base_ = static_cast<AccumulatorT>(baseValue);
    }

    /// @brief Gets raw current value without accumulation.
    /// @return Last updated raw value.
    T getRaw() const
    {
        return lastValue_;
    }

    /// @brief Gets number of rollovers detected.
    /// @return Rollover count.
    AccumulatorT getRolloverCount() const
    {
        return rollover_;
    }

private:
    AccumulatorT base_ = 0;         ///< Base reference value.
    T lastValue_ = 0;              ///< Last raw counter value.
    AccumulatorT rollover_ = 0;     ///< Number of rollovers.
    AccumulatorT directValue_ = 0; ///< Direct additions.
};

/// @brief 32-bit counter with 64-bit accumulator.
using U32Counter = Counter<uint32_t, uint64_t>;

} // namespace snet