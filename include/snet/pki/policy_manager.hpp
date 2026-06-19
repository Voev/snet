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
#include <snet/pki/storage_config.hpp>

#include <casket/utils/noncopyable.hpp>

namespace snet::pki
{

// Структура политики безопасности CA
struct Policy
{
    std::string name;
    std::string caCertPath;
    std::string caKeyPath;
    std::string status;

    Policy() = default;

    Policy(std::string n)
        : name(std::move(n))
        , status("draft")
    {
    }

    Policy(const std::string& n, const std::string& certPath, const std::string& keyPath)
        : name(n)
        , caCertPath(certPath)
        , caKeyPath(keyPath)
        , status("draft")
    {
    }

    bool isComplete() const
    {
        return !caCertPath.empty() && !caKeyPath.empty();
    }

    bool isActive() const
    {
        return status == "active" && isComplete();
    }

    Row toRow() const
    {
        Row row(3);
        row[0] = makeFieldValue(name);
        row[1] = makeFieldValue(caCertPath);
        row[2] = makeFieldValue(caKeyPath);
        return row;
    }

    static Policy fromRow(const Row& row)
    {
        Policy policy;
        if (row.size() >= 3)
        {
            policy.name = getFieldValue<std::string>(row[0]);
            policy.caCertPath = getFieldValue<std::string>(row[1]);
            policy.caKeyPath = getFieldValue<std::string>(row[2]);

            if (!policy.caCertPath.empty() && !policy.caKeyPath.empty())
                policy.status = "active";
            else
                policy.status = "draft";
        }
        return policy;
    }
};

class PolicyManager final : casket::NonCopyable
{
public:
    explicit PolicyManager(const StorageConfig& config);
    ~PolicyManager() noexcept;

    PolicyManager(PolicyManager&&) = default;
    PolicyManager& operator=(PolicyManager&&) = default;

    void createPolicy(const std::string& name);

    void removePolicy(const std::string& name);

    void activatePolicy(const std::string& name);

    void deactivatePolicy(const std::string& name);

    void addKeyToPolicy(std::shared_ptr<Policy> policy, const std::string& keyPath);

    void addCertificateToPolicy(std::shared_ptr<Policy> policy, const std::string& certPath);

    bool hasPolicy(const std::string& name) const;

    std::shared_ptr<Policy> getPolicy(const std::string& name) const;

    std::vector<std::shared_ptr<Policy>> getActivePolicies() const;

    std::vector<std::shared_ptr<Policy>> getDraftPolicies() const;

    struct Stats
    {
        size_t totalPolicies;
        size_t activePolicies;
        size_t inactivePolicies;
        size_t draftPolicies;
        size_t completePolicies;
        size_t policiesWithDirectory;
    };

    Stats getStats() const;

private:

    void loadPolicies();

    bool updatePolicy(const std::string& name, const Policy& policy);

private:
    const StorageConfig& config_;
    std::unique_ptr<TXTDatabase> db_;
    std::map<std::string, std::shared_ptr<Policy>> policies_;
};

} // namespace snet::pki