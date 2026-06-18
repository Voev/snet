#pragma once

#include <string>
#include <map>
#include <memory>
#include <vector>
#include <fstream>
#include <filesystem>
#include <typeindex>
#include <optional>
#include <stdexcept>

#include <snet/utils/file_db.hpp>

namespace snet::pki
{

// Структура политики безопасности CA
struct Policy
{
    std::string name;
    std::string caCertPath;
    std::string caKeyPath;
    std::string status; // "draft", "active", "inactive"

    Policy()
        : status("draft")
    {
    }

    Policy(const std::string& n, const std::string& certPath, const std::string& keyPath)
        : name(n)
        , caCertPath(certPath)
        , caKeyPath(keyPath)
        , status("draft")
    {
    }

    // Проверка состояния
    bool isComplete() const
    {
        return !caCertPath.empty() && !caKeyPath.empty();
    }

    bool isActive() const
    {
        return status == "active" && isComplete();
    }

    // Преобразование в строку для TXTDatabase
    Row toRow() const
    {
        Row row(3);
        row[0] = makeFieldValue(name);
        row[1] = makeFieldValue(caCertPath);
        row[2] = makeFieldValue(caKeyPath);
        return row;
    }

    // Создание Policy из строки TXTDatabase
    static Policy fromRow(const Row& row)
    {
        Policy policy;
        if (row.size() >= 3)
        {
            policy.name = getFieldValue<std::string>(row[0]);
            policy.caCertPath = getFieldValue<std::string>(row[1]);
            policy.caKeyPath = getFieldValue<std::string>(row[2]);

            // Определяем статус на основе наличия файлов
            if (!policy.caCertPath.empty() && !policy.caKeyPath.empty())
                policy.status = "active";
            else
                policy.status = "draft";
        }
        return policy;
    }

private:
    template <typename T>
    static T getFieldValue(const std::shared_ptr<FieldValue>& field)
    {
        auto typed = std::dynamic_pointer_cast<TypedFieldValue<T>>(field);
        if (typed)
            return typed->getValue();
        return T{};
    }
};

// Менеджер политик безопасности
class PolicyManager final
{
public:
    // Типы полей для TXTDatabase
    static std::vector<std::type_index> getFieldTypes()
    {
        return {
            typeid(std::string), // name
            typeid(std::string), // caCertPath
            typeid(std::string)  // caKeyPath
        };
    }

    PolicyManager(const std::string& storageDir)
        : storagePath_(storageDir)
    {
        namespace fs = std::filesystem;

        if (storageDir.empty())
        {
            throw std::runtime_error("Invalid path to storage");
        }

        metadataPath_ = storageDir + "/policies.bin";

        if (fs::exists(storageDir) && fs::exists(metadataPath_))
        {
            try
            {
                db_ = std::make_unique<TXTDatabase>(TXTDatabase::readFromFile(metadataPath_, getFieldTypes()));
                loadPoliciesFromDB();
            }
            catch (const std::exception& e)
            {
                std::cerr << "Warning: Could not load database, creating new one: " << e.what() << std::endl;
                db_ = std::make_unique<TXTDatabase>(getFieldTypes());
            }
        }
        else
        {
            if (!fs::exists(storageDir))
                fs::create_directories(storageDir);

            db_ = std::make_unique<TXTDatabase>(getFieldTypes());
        }

        db_->createIndex(0);
    }

    ~PolicyManager() noexcept
    {
        try
        {
            savePolicies();
        }
        catch (...)
        {
            // Игнорируем ошибки в деструкторе
        }
    }

    // Запрещаем копирование
    PolicyManager(const PolicyManager&) = delete;
    PolicyManager& operator=(const PolicyManager&) = delete;

    // Разрешаем перемещение
    PolicyManager(PolicyManager&&) = default;
    PolicyManager& operator=(PolicyManager&&) = default;

    // ========================================================================
    // Работа с директориями политик
    // ========================================================================

    // Получение пути к директории политики
    std::filesystem::path getPolicyPath(const std::string& name) const
    {
        return std::filesystem::path(storagePath_) / name;
    }

    // Создание директории для политики
    bool createPolicyDirectory(const std::string& name)
    {
        namespace fs = std::filesystem;

        auto policyPath = getPolicyPath(name);

        try
        {
            if (fs::exists(policyPath))
            {
                lastError_ = "Policy directory already exists: " + policyPath.string();
                return false;
            }

            fs::create_directories(policyPath);
            return true;
        }
        catch (const std::exception& e)
        {
            lastError_ = "Failed to create policy directory: " + std::string(e.what());
            return false;
        }
    }

    // Проверка существования директории политики
    bool hasPolicyDirectory(const std::string& name) const
    {
        namespace fs = std::filesystem;
        return fs::exists(getPolicyPath(name)) && fs::is_directory(getPolicyPath(name));
    }

    // Получение стандартных путей для файлов политики
    std::string getDefaultCertPath(const std::string& name) const
    {
        return (getPolicyPath(name) / "ca.crt").string();
    }

    std::string getDefaultKeyPath(const std::string& name) const
    {
        return (getPolicyPath(name) / "ca.key").string();
    }

    std::string getDefaultCSRPath(const std::string& name) const
    {
        return (getPolicyPath(name) / "ca.csr").string();
    }

    // ========================================================================
    // Добавление политики с поддержкой поэтапного создания
    // ========================================================================

    // Вариант 1: Создание политики только с именем (черновик) + директория
    bool createPolicy(const std::string& name)
    {
        if (policies_.find(name) != policies_.end())
        {
            lastError_ = "Policy already exists: " + name;
            return false;
        }

        // Создаем директорию для политики
        if (!createPolicyDirectory(name))
        {
            return false;
        }

        auto policy = std::make_shared<Policy>();
        policy->name = name;
        policy->status = "draft";
        policy->caCertPath = "";
        policy->caKeyPath = "";

        policies_[name] = policy;

        if (!db_->insert(policy->toRow()))
        {
            policies_.erase(name);
            lastError_ = "Failed to insert policy: " + db_->getLastError();
            return false;
        }

        return savePolicies();
    }

    // ========================================================================
    // Дополнение существующей политики
    // ========================================================================

    // Добавление ключа к существующей политике
    bool addKeyToPolicy(const std::string& name, const std::string& keyPath)
    {
        auto policy = getPolicy(name);
        if (!policy)
        {
            lastError_ = "Policy not found: " + name;
            return false;
        }

        if (!policy->caKeyPath.empty())
        {
            lastError_ = "Policy already has a key: " + policy->caKeyPath;
            return false;
        }

        // Проверяем существование директории
        if (!hasPolicyDirectory(name))
        {
            if (!createPolicyDirectory(name))
            {
                return false;
            }
        }

        policy->caKeyPath = keyPath;

        // Если есть сертификат, активируем политику
        if (!policy->caCertPath.empty())
        {
            policy->status = "active";
        }

        return updatePolicy(name, *policy);
    }

    // Добавление сертификата к существующей политике
    bool addCertificateToPolicy(const std::string& name, const std::string& certPath)
    {
        auto policy = getPolicy(name);
        if (!policy)
        {
            lastError_ = "Policy not found: " + name;
            return false;
        }

        if (!policy->caCertPath.empty())
        {
            lastError_ = "Policy already has a certificate: " + policy->caCertPath;
            return false;
        }

        // Проверяем существование директории
        if (!hasPolicyDirectory(name))
        {
            if (!createPolicyDirectory(name))
            {
                return false;
            }
        }

        policy->caCertPath = certPath;

        // Если есть ключ, активируем политику
        if (!policy->caKeyPath.empty())
        {
            policy->status = "active";
        }

        return updatePolicy(name, *policy);
    }

    // ========================================================================
    // Операции с политиками
    // ========================================================================

    // Получение политики по имени (используем индекс)
    std::shared_ptr<Policy> getPolicy(const std::string& name) const
    {
        auto it = policies_.find(name);
        if (it != policies_.end())
        {
            return it->second;
        }

        auto fieldValue = makeFieldValue(name);
        const Row* row = db_->findByIndex(0, fieldValue);
        if (row)
        {
            Policy policy = Policy::fromRow(*row);
            auto sharedPolicy = std::make_shared<Policy>(policy);
            const_cast<PolicyManager*>(this)->policies_[name] = sharedPolicy;
            return sharedPolicy;
        }

        return nullptr;
    }

    // Получение всех активных политик
    std::vector<std::shared_ptr<Policy>> getActivePolicies() const
    {
        std::vector<std::shared_ptr<Policy>> result;
        for (const auto& [name, policy] : policies_)
        {
            if (policy && policy->isActive())
            {
                result.push_back(policy);
            }
        }
        return result;
    }

    // Получение всех черновиков (неполных политик)
    std::vector<std::shared_ptr<Policy>> getDraftPolicies() const
    {
        std::vector<std::shared_ptr<Policy>> result;
        for (const auto& [name, policy] : policies_)
        {
            if (policy && !policy->isComplete())
            {
                result.push_back(policy);
            }
        }
        return result;
    }

    // Деактивация политики
    bool deactivatePolicy(const std::string& name)
    {
        auto policy = getPolicy(name);
        if (!policy)
        {
            lastError_ = "Policy not found: " + name;
            return false;
        }

        if (!policy->isActive())
        {
            lastError_ = "Policy is not active. Current status: " + policy->status;
            return false;
        }

        policy->status = "inactive";

        return updatePolicy(name, *policy);
    }

    // Активация политики
    bool activatePolicy(const std::string& name)
    {
        auto policy = getPolicy(name);
        if (!policy)
        {
            lastError_ = "Policy not found: " + name;
            return false;
        }

        if (!policy->isComplete())
        {
            lastError_ = "Cannot activate incomplete policy. Missing key or certificate.";
            return false;
        }

        policy->status = "active";

        return updatePolicy(name, *policy);
    }

    // Удаление политики (включая директорию)
    bool removePolicy(const std::string& name)
    {
        namespace fs = std::filesystem;

        auto it = policies_.find(name);
        if (it == policies_.end())
        {
            lastError_ = "Policy not found: " + name;
            return false;
        }

        // Удаляем из БД
        auto fieldValue = makeFieldValue(name);
        if (!db_->removeByIndex(0, fieldValue))
        {
            lastError_ = "Failed to remove policy from database: " + db_->getLastError();
            return false;
        }

        policies_.erase(it);

        // Удаляем директорию политики
        try
        {
            auto policyPath = getPolicyPath(name);
            if (fs::exists(policyPath))
            {
                fs::remove_all(policyPath);
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << "Warning: Failed to remove policy directory: " << e.what() << std::endl;
            // Не возвращаем ошибку, так как политика уже удалена из БД
        }

        return savePolicies();
    }

    // Получение списка всех политик
    std::vector<std::string> listPolicies() const
    {
        std::vector<std::string> names;
        for (const auto& [name, _] : policies_)
        {
            names.push_back(name);
        }
        return names;
    }

    // Получение статистики
    struct Stats
    {
        size_t totalPolicies;
        size_t activePolicies;
        size_t inactivePolicies;
        size_t draftPolicies;
        size_t completePolicies;
        size_t policiesWithDirectory;
    };

    Stats getStats() const
    {
        Stats stats{0, 0, 0, 0, 0, 0};
        for (const auto& [name, policy] : policies_)
        {
            stats.totalPolicies++;

            if (policy->status == "active")
                stats.activePolicies++;
            else if (policy->status == "inactive")
                stats.inactivePolicies++;
            else if (policy->status == "draft")
                stats.draftPolicies++;

            if (policy->isComplete())
                stats.completePolicies++;

            if (hasPolicyDirectory(name))
                stats.policiesWithDirectory++;
        }
        return stats;
    }

    // Сохранение всех политик
    bool savePolicies() noexcept
    {
        try
        {
            db_->clear();

            for (const auto& [name, policy] : policies_)
            {
                if (!db_->insert(policy->toRow()))
                {
                    std::cerr << "Failed to insert policy " << name << ": " << db_->getLastError() << std::endl;
                    return false;
                }
            }

            db_->writeToFile(metadataPath_);
            return true;
        }
        catch (const std::exception& e)
        {
            std::cerr << "Error saving policies: " << e.what() << std::endl;
            return false;
        }
    }

    // Получение пути к хранилищу
    const std::string& getStoragePath() const
    {
        return storagePath_;
    }

    // Получение последней ошибки
    std::string getLastError() const
    {
        return lastError_;
    }

    // Проверка существования политики
    bool hasPolicy(const std::string& name) const
    {
        return policies_.find(name) != policies_.end();
    }

private:
    std::map<std::string, std::shared_ptr<Policy>> policies_;
    std::string storagePath_;
    std::string metadataPath_;
    std::unique_ptr<TXTDatabase> db_;
    mutable std::string lastError_;

    void loadPoliciesFromDB()
    {
        policies_.clear();
        for (size_t i = 0; i < db_->size(); i++)
        {
            const auto& row = db_->getRow(i);
            Policy policy = Policy::fromRow(row);
            policies_[policy.name] = std::make_shared<Policy>(policy);
        }
    }

    bool updatePolicy(const std::string& name, const Policy& policy)
    {
        policies_[name] = std::make_shared<Policy>(policy);

        for (size_t i = 0; i < db_->size(); i++)
        {
            const auto& row = db_->getRow(i);
            if (row.size() >= 1)
            {
                auto rowName = getFieldValue<std::string>(row[0]);
                if (rowName == name)
                {
                    if (!db_->updateRow(i, policy.toRow()))
                    {
                        lastError_ = "Failed to update policy in database: " + db_->getLastError();
                        return false;
                    }
                    return savePolicies();
                }
            }
        }

        lastError_ = "Policy not found in database";
        return false;
    }

    template <typename T>
    static T getFieldValue(const std::shared_ptr<FieldValue>& field)
    {
        auto typed = std::dynamic_pointer_cast<TypedFieldValue<T>>(field);
        if (typed)
            return typed->getValue();
        return T{};
    }
};

} // namespace snet::pki