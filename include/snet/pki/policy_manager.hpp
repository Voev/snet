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

#include <snet/pki/storage_config.hpp>

#include <casket/db/i_database.hpp>
#include <casket/utils/noncopyable.hpp>

namespace snet::pki
{

enum class PolicyStatus : uint32_t
{
    CREATED = 0,   // Policy created, no components added yet
    KEY_ADDED = 1, // Private key added
    COMPLETE = 2,  // Both key and certificate present
    ENABLED = 3,   // Policy is active and ready to use
    DISABLED = 4,  // Policy disabled by administrator
    NOT_VALID = 5  // Certificate expired or invalid
};

struct Policy
{
    std::string name;
    std::string caCertPath;
    std::string caKeyPath;
    PolicyStatus status;

    Policy();

    Policy(const std::string& n);

    bool hasKey() const;

    bool hasCertificate() const;

    bool isComplete() const;

    bool isExpired() const;

    bool isReady() const;

    bool canSign() const;

    void updateStatus();

    void addKey(const std::string& keyPath);

    void addCertificate(const std::string& certPath);

    void enable();

    void disable();

    void markNotValid();

    void restore();

    std::shared_ptr<casket::db::IRow> toRow() const;

    static Policy fromRow(const casket::db::IRow& row);

    static nonstd::string_view statusToString(PolicyStatus status);

    void print(std::ostream& os) const;
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

    void enablePolicy(std::shared_ptr<Policy> policy);

    void disablePolicy(std::shared_ptr<Policy> policy);

    void addKeyToPolicy(std::shared_ptr<Policy> policy, const std::string& keyPath);

    void addCertificateToPolicy(std::shared_ptr<Policy> policy, const std::string& certPath);

    bool hasPolicy(const std::string& name) const;

    std::shared_ptr<Policy> getPolicy(const std::string& name) const;

    std::vector<std::shared_ptr<Policy>> getReadyPolicies() const;

    std::vector<std::shared_ptr<Policy>> getAllPolicies() const;

private:
    void loadPolicies();

    bool updatePolicy(const std::string& name, const Policy& policy);

private:
    const StorageConfig& config_;
    std::unique_ptr<casket::db::IDatabase> db_;
    std::map<std::string, std::shared_ptr<Policy>> policies_;
};

} // namespace snet::pki