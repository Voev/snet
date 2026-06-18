// transactional_file_impl.h
#pragma once

#include <snet/transaction/strategies.hpp>

namespace txfile
{

template <typename T>
class TransactionalFile
{
public:
    // Конфигурация
    struct Config
    {
        bool enableBackup = true;
        size_t maxRetryAttempts = 3;
        std::chrono::milliseconds retryDelay{100};
        size_t maxBackupCount = 5;
    };

    // Транзакция
    class Transaction
    {
    public:
        enum class Status
        {
            Active,
            Prepared,
            Committed,
            RolledBack,
            Aborted
        };

        // Применить операцию
        template <typename Op, typename... Args>
        Transaction& apply(Args&&... args)
        {
            static_assert(std::is_base_of_v<IDataOperation<T>, Op>, "Operation must derive from IDataOperation");
            operations_.push_back(std::make_unique<Op>(std::forward<Args>(args)...));
            return *this;
        }

        // Применить лямбда-операцию
        Transaction& apply(std::function<void(T&)> func, std::function<void(T&)> rollbackFunc = nullptr,
                           std::function<bool(const T&)> validator = nullptr)
        {
            operations_.push_back(std::make_unique<LambdaOperation>(func, rollbackFunc, validator));
            return *this;
        }

        // Получить снапшот
        const T& snapshot() const
        {
            return snapshot_;
        }
        T& mutableSnapshot()
        {
            return snapshot_;
        }

        // Получить статус
        Status getStatus() const
        {
            return status_;
        }
        uint64_t getId() const
        {
            return id_;
        }

    private:
        friend class TransactionalFile;

        Transaction(uint64_t id, T snapshot, T base)
            : id_(id)
            , snapshot_(std::move(snapshot))
            , base_(std::move(base))
            , status_(Status::Active)
        {
        }

        class LambdaOperation : public IDataOperation<T>
        {
        public:
            LambdaOperation(std::function<void(T&)> func, std::function<void(T&)> rollback,
                            std::function<bool(const T&)> validator)
                : func_(std::move(func))
                , rollback_(std::move(rollback))
                , validator_(std::move(validator))
            {
            }

            void apply(T& data) override
            {
                if (func_)
                    func_(data);
            }
            void rollback(T& data) override
            {
                if (rollback_)
                    rollback_(data);
            }
            bool validate(const T& data) const override
            {
                return validator_ ? validator_(data) : true;
            }

        private:
            std::function<void(T&)> func_;
            std::function<void(T&)> rollback_;
            std::function<bool(const T&)> validator_;
        };

        uint64_t id_;
        T snapshot_;
        T base_;
        Status status_;
        std::vector<std::unique_ptr<IDataOperation<T>>> operations_;
    };

    // Конструктор
    TransactionalFile(const std::string& filePath, std::unique_ptr<IPersistenceStrategy> persistence = nullptr,
                      std::unique_ptr<ILockStrategy> lockStrategy = nullptr,
                      std::unique_ptr<IMergeProvider<T>> mergeProvider = nullptr, Config config = {})
        : filePath_(filePath)
        , config_(std::move(config))
    {

        // Создаем стратегии по умолчанию если не предоставлены
        if (!persistence)
        {
            persistence_ = std::make_unique<FileSystemPersistence>(filePath);
        }
        else
        {
            persistence_ = std::move(persistence);
        }

        if (!lockStrategy)
        {
            lockStrategy_ = std::make_unique<FileLockStrategy>(filePath + ".lock");
        }
        else
        {
            lockStrategy_ = std::move(lockStrategy);
        }

        if (!mergeProvider)
        {
            mergeProvider_ = std::make_unique<LastWriteWinsMergeProvider<T>>();
        }
        else
        {
            mergeProvider_ = std::move(mergeProvider);
        }

        // Загружаем существующие данные
        load();
    }

    // Создать транзакцию
    std::shared_ptr<Transaction> beginTransaction()
    {
        std::shared_lock lock(dataMutex_);

        T snapshot = committedData_.data;
        T base = committedData_.data;

        auto txnId = nextTransactionId_++;
        auto txn = std::make_shared<Transaction>(txnId, std::move(snapshot), std::move(base));

        {
            std::lock_guard txLock(transactionMutex_);
            activeTransactions_[txnId] = txn;
        }

        return txn;
    }

    // Выполнить транзакцию с автоматическими повторами
    template <typename Func>
    TransactionResult withTransaction(Func&& func)
    {
        for (size_t attempt = 0; attempt < config_.maxRetryAttempts; ++attempt)
        {
            auto txn = beginTransaction();

            try
            {
                func(*txn);

                if (prepare(txn))
                {
                    if (commit(txn))
                    {
                        return TransactionResult::Success;
                    }
                }
                else
                {
                    rollback(txn);
                    return TransactionResult::ValidationError;
                }
            }
            catch (const std::exception&)
            {
                rollback(txn);
                return TransactionResult::ValidationError;
            }

            // Конфликт или ошибка - повторяем
            if (attempt < config_.maxRetryAttempts - 1)
            {
                std::this_thread::sleep_for(config_.retryDelay);
            }
        }

        return TransactionResult::Conflict;
    }

    // Подготовка транзакции
    bool prepare(std::shared_ptr<Transaction> txn)
    {
        if (txn->status_ != Transaction::Status::Active)
        {
            return false;
        }

        // Применяем операции к снапшоту
        for (auto& op : txn->operations_)
        {
            if (!op->validate(txn->snapshot_))
            {
                txn->status_ = Transaction::Status::Aborted;
                return false;
            }
            op->apply(txn->snapshot_);
        }

        // Валидация через провайдер слияния
        if (!mergeProvider_->validate(txn->snapshot_))
        {
            txn->status_ = Transaction::Status::Aborted;
            return false;
        }

        txn->status_ = Transaction::Status::Prepared;

        return true;
    }

    // Коммит транзакции
    bool commit(std::shared_ptr<Transaction> txn)
    {
        if (txn->status_ != Transaction::Status::Prepared)
        {
            return false;
        }

        // Получаем блокировку на запись
        if (!lockStrategy_->acquireWrite())
        {
            txn->status_ = Transaction::Status::Aborted;
            return false;
        }

        bool success = false;

        {
            std::unique_lock lock(dataMutex_);

            // Проверяем оптимистическую блокировку
            if (!validateTransaction(txn))
            {
                lockStrategy_->release();
                txn->status_ = Transaction::Status::Aborted;
                return false;
            }

            // Выполняем слияние
            T merged = mergeProvider_->merge(txn->base_, txn->snapshot_, committedData_.data);

            // Проверяем конфликты
            bool hasConflicts = mergeProvider_->hasConflicts(txn->base_, txn->snapshot_, committedData_.data);

            if (hasConflicts)
            {
                // В реальной системе здесь можно вызвать обработчик конфликтов
                // или сохранить конфликтующие данные
            }

            // Применяем слитые данные
            committedData_.data = std::move(merged);
            committedData_.increment();

            txn->status_ = Transaction::Status::Committed;
            success = true;
        }

        // Сохраняем на диск
        if (success)
        {
            success = save();
            if (!success)
            {
                throw std::runtime_error("Failed to persist committed data");
            }
        }

        // Освобождаем блокировку
        lockStrategy_->release();

        // Очищаем транзакцию
        {
            std::lock_guard txLock(transactionMutex_);
            activeTransactions_.erase(txn->getId());
        }

        commitCV_.notify_all();

        if (success)
        {
            // Создаем бэкап если нужно
            if (config_.enableBackup)
            {
                persistence_->createBackup();
            }
        }

        return success;
    }

    // Откат транзакции
    bool rollback(std::shared_ptr<Transaction> txn)
    {
        if (txn->status_ == Transaction::Status::Committed)
        {
            return false;
        }

        // Откатываем операции в обратном порядке
        for (auto it = txn->operations_.rbegin(); it != txn->operations_.rend(); ++it)
        {
            (*it)->rollback(txn->snapshot_);
        }

        txn->status_ = Transaction::Status::RolledBack;

        {
            std::lock_guard txLock(transactionMutex_);
            activeTransactions_.erase(txn->getId());
        }

        commitCV_.notify_all();

        return true;
    }

    // Получить текущий снапшот данных
    T getSnapshot() const
    {
        std::shared_lock lock(dataMutex_);
        return committedData_.data;
    }

    // Принудительно сохранить на диск
    bool forceSave()
    {
        std::shared_lock lock(dataMutex_);
        return save();
    }

    // Загрузить с диска
    bool load()
    {
        auto data = persistence_->load();
        if (data)
        {
            std::unique_lock lock(dataMutex_);
            // Здесь должна быть десериализация
            // committedData_.data = T::deserialize(*data);
            committedData_.increment();
            return true;
        }
        return false;
    }

    // Подождать завершения всех транзакций
    void waitForAllTransactions()
    {
        std::unique_lock<std::mutex> lock(transactionMutex_);
        commitCV_.wait(lock, [this]() { return activeTransactions_.empty(); });
    }

private:
    bool validateTransaction(const std::shared_ptr<Transaction>& txn)
    {
        // Проверяем что базовая версия не изменилась
        // В простом случае - всегда true (Last-Write-Wins)
        return true;
    }

    bool save()
    {
        // Здесь должна быть сериализация данных
        // std::string data = committedData_.data.serialize();
        // return persistence_->save(data);
        return persistence_->save(""); // Заглушка
    }

    std::string filePath_;
    Config config_;

    std::unique_ptr<IPersistenceStrategy> persistence_;
    std::unique_ptr<ILockStrategy> lockStrategy_;
    std::unique_ptr<IMergeProvider<T>> mergeProvider_;

    VersionedData<T> committedData_;
    mutable std::shared_mutex dataMutex_;
    std::mutex transactionMutex_;
    std::condition_variable commitCV_;

    std::atomic<uint64_t> nextTransactionId_{1};
    std::unordered_map<uint64_t, std::shared_ptr<Transaction>> activeTransactions_;
};

} // namespace txfile