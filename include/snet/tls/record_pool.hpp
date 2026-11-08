#pragma once
#include <cassert>
#include <memory>
#include <vector>

#include <snet/tls/record.hpp>

namespace snet::tls
{

class RecordPool
{
public:
    /// @brief RAII owner of a Record, with std::unique_ptr-like semantics.
    ///
    /// - `release()`: relinquish ownership WITHOUT returning to the pool.
    ///   The caller becomes responsible for eventually calling
    ///   `RecordPool::release(record)`.
    /// - `reset(p = nullptr)`: return the current record to the pool (if
    ///   any) and adopt `p`.
    /// - Destructor: calls `reset()`, returning the record to the pool.
    ///
    /// Move-only.
    class ScopedRecord
    {
    public:
        using pointer = Record*;

        constexpr ScopedRecord() noexcept = default;
        constexpr ScopedRecord(std::nullptr_t) noexcept {}

        explicit ScopedRecord(pointer record, RecordPool* pool) noexcept
            : record_(record)
            , pool_(pool)
        {
        }

        ScopedRecord(const ScopedRecord&)            = delete;
        ScopedRecord& operator=(const ScopedRecord&) = delete;

        ScopedRecord(ScopedRecord&& other) noexcept
            : record_(other.record_)
            , pool_(other.pool_)
        {
            other.record_ = nullptr;
            other.pool_   = nullptr;
        }

        ScopedRecord& operator=(ScopedRecord&& other) noexcept
        {
            if (this != &other)
            {
                reset();
                record_ = other.record_;
                pool_   = other.pool_;
                other.record_ = nullptr;
                other.pool_   = nullptr;
            }
            return *this;
        }

        ~ScopedRecord() noexcept
        {
            reset();
        }

        /// @brief Get the raw pointer without transferring ownership.
        pointer get() const noexcept { return record_; }

        /// @brief Relinquish ownership WITHOUT returning to the pool.
        ///        The caller must eventually release the record manually.
        pointer release() noexcept
        {
            pointer p = record_;
            record_   = nullptr;
            pool_     = nullptr;
            return p;
        }

        /// @brief Return the current record to the pool (if any) and adopt @p p.
        ///        @p p is returned to the pool on next reset/destruction.
        void reset(pointer p = nullptr) noexcept
        {
            if (record_ && pool_)
                pool_->release(record_);
            record_ = p;
            if (!p)
                pool_ = nullptr;
        }

        explicit operator bool() const noexcept { return record_ != nullptr; }

        pointer operator->() const noexcept
        {
            assert(record_);
            return record_;
        }

        Record& operator*() const noexcept
        {
            assert(record_);
            return *record_;
        }

        void swap(ScopedRecord& other) noexcept
        {
            std::swap(record_, other.record_);
            std::swap(pool_,   other.pool_);
        }

    private:
        pointer     record_ = nullptr;
        RecordPool* pool_   = nullptr;
    };

    explicit RecordPool(size_t fixed_size)
        : records_(fixed_size)
    {
        free_records_.reserve(fixed_size);
        for (auto& record : records_)
        {
            record = std::make_unique<Record>();
            free_records_.push_back(record.get());
        }
    }

    ~RecordPool() = default;

    Record* acquire() noexcept
    {
        if (free_records_.empty())
            return nullptr;
        Record* record = free_records_.back();
        free_records_.pop_back();
        record->reset();
        return record;
    }

    ScopedRecord acquireScoped() noexcept
    {
        return ScopedRecord(acquire(), this);
    }

    void release(Record* record) noexcept
    {
        if (!record)
            return;
        assert(is_from_pool(record));

        if (secureErase_)
            record->secureErasePlaintext();

        free_records_.push_back(record);
    }

    void setSecureErase(bool enable) noexcept { secureErase_ = enable; }

    size_t size()      const { return records_.size(); }
    size_t available() const { return free_records_.size(); }

private:
    bool is_from_pool(Record* record) const
    {
        auto it = std::find_if(records_.begin(), records_.end(),
                                [record](const auto& p) { return p.get() == record; });
        return it != records_.end();
    }

    std::vector<std::unique_ptr<Record>> records_;
    std::vector<Record*>                 free_records_;
    bool                                 secureErase_ = false;
};

} // namespace snet::tls