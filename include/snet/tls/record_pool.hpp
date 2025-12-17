#pragma once
#include <cassert>
#include <snet/tls/record.hpp>

namespace snet::tls
{

class RecordPool
{
public:
    class ScopedRecord
    {
    public:
        ScopedRecord() = default;

        ScopedRecord(Record* record, RecordPool* pool)
            : record_(record)
            , pool_(pool)
        {
        }

        ScopedRecord(const ScopedRecord&) = delete;
        ScopedRecord& operator=(const ScopedRecord&) = delete;

        ScopedRecord(ScopedRecord&& other) noexcept
            : record_(other.record_)
            , pool_(other.pool_)
        {
            other.record_ = nullptr;
            other.pool_ = nullptr;
        }

        ScopedRecord& operator=(ScopedRecord&& other) noexcept
        {
            if (this != &other)
            {
                release();
                record_ = other.record_;
                pool_ = other.pool_;
                other.record_ = nullptr;
                other.pool_ = nullptr;
            }
            return *this;
        }

        ~ScopedRecord()
        {
            release();
        }

        // Явный release
        void release() noexcept
        {
            if (record_ && pool_)
            {
                pool_->release(record_);
                record_ = nullptr;
                pool_ = nullptr;
            }
        }

        // Получение указателя на Record
        Record* get() const noexcept
        {
            return record_;
        }

        // Операторы доступа
        Record* operator->() const noexcept
        {
            assert(record_);
            return record_;
        }

        Record& operator*() const noexcept
        {
            assert(record_);
            return *record_;
        }

        // Проверка наличия записи
        explicit operator bool() const noexcept
        {
            return record_ != nullptr;
        }

    private:
        Record* record_ = nullptr;
        RecordPool* pool_ = nullptr;
    };

    explicit RecordPool(size_t fixed_size)
        : records_(fixed_size)
    {
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
        {
            return nullptr;
        }

        Record* record = free_records_.back();
        free_records_.pop_back();
        record->reset();
        return record;
    }

    ScopedRecord acquireScoped() noexcept
    {
        Record* record = acquire();
        return ScopedRecord(record, this);
    }

    void release(Record* record) noexcept
    {
        if (!record)
            return;

        assert(is_from_pool(record));
        record->reset();
        free_records_.push_back(record);
    }

    size_t size() const
    {
        return records_.size();
    }

    size_t available() const
    {
        return free_records_.size();
    }

private:
    bool is_from_pool(Record* record) const
    {
        auto it =
            std::find_if(records_.begin(), records_.end(), [record](const auto& ptr) { return ptr.get() == record; });
        return it != records_.end();
    }

private:
    std::vector<std::unique_ptr<Record>> records_;
    std::vector<Record*> free_records_;
};

} // namespace snet::tls