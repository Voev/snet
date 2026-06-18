#pragma once
#include <cstdint>
#include <chrono>
#include <snet/transaction/data_operation.hpp>
#include <snet/transaction/lock_strategy.hpp>
#include <snet/transaction/persistance_strategy.hpp>


template <typename T>
struct VersionedData
{
    T data;
    uint64_t version{0};
    std::chrono::system_clock::time_point timestamp;

    void increment()
    {
        ++version;
        timestamp = std::chrono::system_clock::now();
    }
};

enum class TransactionResult
{
    Success,
    Conflict,
    ValidationError,
    LockError,
    PersistenceError,
    Timeout
};
