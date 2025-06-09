#pragma once
#include <cassert>
#include <snet/tls/record.hpp>

namespace snet::tls
{

class RecordPool
{
public:
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

} //