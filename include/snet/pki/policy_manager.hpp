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
#include <snet/pki/policy.hpp>
#include <snet/pki/storage_config.hpp>

#include <casket/utils/noncopyable.hpp>

namespace snet::pki
{

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
    TXTDatabase db_;
    std::map<std::string, std::shared_ptr<Policy>> policies_;
};

} // namespace snet::pki