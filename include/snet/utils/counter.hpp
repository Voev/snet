#pragma once
#include <cstdint>
#include <limits>
#include <type_traits>

namespace snet
{

template <typename T, typename AccumulatorT = uint64_t>
class Counter
{
    static_assert(std::is_unsigned_v<T>, "T must be unsigned integer type");
    static_assert(std::is_unsigned_v<AccumulatorT>, "AccumulatorT must be unsigned integer type");
    static_assert(sizeof(AccumulatorT) > sizeof(T), "AccumulatorT must be larger than T");

public:
    Counter() = default;

    explicit Counter(T base_value)
        : base_(base_value)
        , last_value_(base_value)
    {
    }

    void update(T new_value)
    {
        if (new_value < last_value_)
        {
            rollover_ += static_cast<AccumulatorT>(std::numeric_limits<T>::max()) + 1;
        }
        last_value_ = new_value;
    }

    void add(AccumulatorT increment)
    {
        direct_value_ += increment;
    }

    AccumulatorT get() const
    {
        return rollover_ + static_cast<AccumulatorT>(last_value_) + direct_value_;
    }

    AccumulatorT getRelative() const
    {
        return rollover_ + static_cast<AccumulatorT>(last_value_) + direct_value_ - base_;
    }

    void reset(T base_value = 0)
    {
        base_ = static_cast<AccumulatorT>(base_value);
        last_value_ = base_value;
        rollover_ = 0;
        direct_value_ = 0;
    }

    void setBase(T base_value)
    {
        base_ = static_cast<AccumulatorT>(base_value);
    }

    T getRaw() const
    {
        return last_value_;
    }

    AccumulatorT getRolloverCount() const
    {
        return rollover_;
    }

private:
    AccumulatorT base_ = 0;
    T last_value_ = 0;
    AccumulatorT rollover_ = 0;
    AccumulatorT direct_value_ = 0;
};

using U32Counter = Counter<uint32_t, uint64_t>;

}