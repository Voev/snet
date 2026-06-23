#include <snet/pki/policy_manager.hpp>

#include <casket/log/log.hpp>
#include <casket/utils/action_chain.hpp>
#include <casket/utils/exception.hpp>

namespace fs = std::filesystem;

namespace snet::pki
{

static inline std::vector<std::type_index> GetFieldTypes()
{
    return {
        typeid(std::string), // name
        typeid(std::string), // caCertPath
        typeid(std::string), // caKeyPath
        typeid(std::uint32_t) // status
    };
}

static inline TXTDatabase CreateDatabase(const StorageConfig& config)
{
    auto metadataPath = config.getPolicyMetadataPath();

    if (fs::exists(metadataPath))
    {
        return TXTDatabase::readFromFile(metadataPath, GetFieldTypes());
    }
    else
    {
        return TXTDatabase(GetFieldTypes());
    }
}

PolicyManager::PolicyManager(const StorageConfig& config)
    : config_(config)
    , db_(CreateDatabase(config))
{
    db_.createIndex(0);

    loadPolicies();
}

PolicyManager::~PolicyManager() noexcept
{
}

void PolicyManager::createPolicy(const std::string& name)
{
    casket::ThrowIfTrue(policies_.find(name) != policies_.end(), "policy '{}' already created", name);
    casket::ActionChain chain;

    auto path = config_.getPolicyPath(name);
    chain.addAction(
        [&]()
        {
            CSK_LOG_DEBUG("creating directory '%s'", path.string().c_str());
            fs::create_directories(path);
        },
        [&]()
        {
            CSK_LOG_DEBUG("removing directory '%s'", path.string().c_str());
            std::error_code ec;
            fs::remove_all(path, ec);
        });

    auto policy = std::make_shared<Policy>(name);
    chain.addAction(
        [&]()
        {
            CSK_LOG_DEBUG("inserting entry '%s'", name.c_str());
            casket::ThrowIfFalse(db_.insert(policy->toRow()),
                                 "{} row: {}, field: {}",
                                 db_.getLastError(),
                                 db_.getErrorRow(),
                                 db_.getErrorField());
        },
        [&]()
        {
            CSK_LOG_DEBUG("removing entry '%s'", name.c_str());
            auto fieldValue = makeFieldValue(name);
            casket::ThrowIfFalse(db_.removeByIndex(0, fieldValue), "{}", db_.getLastError());
        });

    chain.addAction(
        [&]()
        {
            CSK_LOG_DEBUG("inserting entry into cache '%s'", name.c_str());
            policies_[name] = policy;
        },
        [&]()
        {
            CSK_LOG_DEBUG("removing entry from cache '%s'", name.c_str());
            policies_.erase(name);
        });

    chain.addAction(
        [&]()
        {
            CSK_LOG_DEBUG("writing entry into database '%s'", name.c_str());
            auto metadataPath = config_.getPolicyMetadataPath();
            db_.writeToFile(metadataPath);
        });

    chain.execute();
}

void PolicyManager::removePolicy(const std::string& name)
{
    casket::ThrowIfTrue(policies_.find(name) == policies_.end(), "policy '{}' does not exist", name);

    auto policy = policies_[name];
    auto policyRow = policy->toRow();
    auto policyPath = config_.getPolicyPath(name);
    bool dirExists = fs::exists(policyPath);

    casket::ActionChain chain;

    chain.addAction(
        [&]()
        {
            policies_.erase(name);
        },
        [&]()
        {
            policies_[name] = policy;
        });

    chain.addAction(
        [&]()
        {
            auto fieldValue = makeFieldValue(name);
            casket::ThrowIfFalse(db_.removeByIndex(0, fieldValue), "{}", db_.getLastError());
        },
        [&]()
        {
            db_.insert(policyRow);
        });

    chain.addAction(
        [&]()
        {
            auto metadataPath = config_.getPolicyMetadataPath();
            db_.writeToFile(metadataPath);
        });

    chain.addAction(
        [&]()
        {
            if (dirExists)
            {
                std::error_code ec;
                fs::remove_all(policyPath, ec);
            }
        });

    chain.execute();
}

void PolicyManager::enablePolicy(std::shared_ptr<Policy> policy)
{
    casket::ActionChain chain;

    auto oldStatus = policy->status;

    chain.addAction(
        [&]()
        {
            CSK_LOG_DEBUG("enabling policy '%s'", policy->name.c_str());
            policy->enable();
        },
        [&]()
        {
            CSK_LOG_DEBUG("rollback: restoring status for policy '%s' to '%d'", policy->name.c_str(), (int)oldStatus);
            policy->status = oldStatus;
        });

    chain.addAction(
        [&]()
        {
            CSK_LOG_DEBUG("updating policy '%s' in database", policy->name.c_str());
            casket::ThrowIfFalse(
                updatePolicy(policy->name, *policy), "failed to update policy '%s' in database", policy->name.c_str());
        },
        [&]()
        {
            CSK_LOG_DEBUG("rollback: restoring policy '%s' in database", policy->name.c_str());
            auto oldPolicy = *policy;
            oldPolicy.status = oldStatus;
            casket::ThrowIfFalse(updatePolicy(policy->name, oldPolicy),
                                 "failed to rollback policy '{}' in database",
                                 policy->name.c_str());
        });

    chain.addAction(
        [&]()
        {
            CSK_LOG_DEBUG("saving policies to file");
            auto metadataPath = config_.getPolicyMetadataPath();
            db_.writeToFile(metadataPath);
        });

    chain.execute();

    CSK_LOG_INFO("policy '%s' enabled successfully", policy->name.c_str());
}

void PolicyManager::disablePolicy(std::shared_ptr<Policy> policy)
{
    casket::ActionChain chain;

    auto oldStatus = policy->status;

    chain.addAction(
        [&]()
        {
            CSK_LOG_DEBUG("disabling policy '%s'", policy->name.c_str());
            policy->disable();
        },
        [&]()
        {
            CSK_LOG_DEBUG("rollback: restoring status for policy '%s' to '%d'", policy->name.c_str(), (int)oldStatus);
            policy->status = oldStatus;
        });

    chain.addAction(
        [&]()
        {
            CSK_LOG_DEBUG("updating policy '%s' in database", policy->name.c_str());
            casket::ThrowIfFalse(
                updatePolicy(policy->name, *policy), "failed to update policy '{}' in database", policy->name.c_str());
        },
        [&]()
        {
            CSK_LOG_DEBUG("rollback: restoring policy '%s' in database", policy->name.c_str());
            auto oldPolicy = *policy;
            oldPolicy.status = oldStatus;
            casket::ThrowIfFalse(updatePolicy(policy->name, oldPolicy),
                                 "failed to rollback policy '{}' in database",
                                 policy->name.c_str());
        });

    chain.addAction(
        [&]()
        {
            CSK_LOG_DEBUG("saving policies to file");
            auto metadataPath = config_.getPolicyMetadataPath();
            db_.writeToFile(metadataPath);
        });

    chain.execute();

    CSK_LOG_INFO("policy '%s' deactivated successfully", policy->name.c_str());
}

void PolicyManager::addKeyToPolicy(std::shared_ptr<Policy> policy, const std::string& keyPath)
{
    casket::ActionChain chain;

    auto oldKeyPath = policy->caKeyPath;
    auto oldStatus = policy->status;

    chain.addAction(
        [&]()
        {
            policy->addKey(keyPath);
        },
        [&]()
        {
            policy->caKeyPath = oldKeyPath;
            policy->status = oldStatus;
        });

    chain.addAction(
        [&]()
        {
            casket::ThrowIfFalse(updatePolicy(policy->name, *policy), "failed to update policy in database");
        });

    chain.addAction(
        [&]()
        {
            auto metadataPath = config_.getPolicyMetadataPath();
            db_.writeToFile(metadataPath);
        });

    chain.execute();
}

void PolicyManager::addCertificateToPolicy(std::shared_ptr<Policy> policy, const std::string& certPath)
{
    casket::ActionChain chain;

    auto oldCertPath = policy->caCertPath;
    auto oldStatus = policy->status;

    chain.addAction(
        [&]()
        {
            policy->addCertificate(certPath);
        },
        [&]()
        {
            policy->caCertPath = oldCertPath;
            policy->status = oldStatus;
        });

    chain.addAction(
        [&]()
        {
            casket::ThrowIfFalse(updatePolicy(policy->name, *policy), "failed to update policy in database");
        });

    chain.addAction(
        [&]()
        {
            auto metadataPath = config_.getPolicyMetadataPath();
            db_.writeToFile(metadataPath);
        });

    chain.execute();
}

std::shared_ptr<Policy> PolicyManager::getPolicy(const std::string& name) const
{
    auto it = policies_.find(name);
    if (it != policies_.end())
    {
        return it->second;
    }

    auto fieldValue = makeFieldValue(name);
    const Row* row = db_.findByIndex(0, fieldValue);
    if (row)
    {
        Policy policy = Policy::fromRow(*row);
        auto sharedPolicy = std::make_shared<Policy>(policy);
        const_cast<PolicyManager*>(this)->policies_[name] = sharedPolicy;
        return sharedPolicy;
    }

    return nullptr;
}

bool PolicyManager::hasPolicy(const std::string& name) const
{
    return policies_.find(name) != policies_.end();
}

std::vector<std::shared_ptr<Policy>> PolicyManager::getReadyPolicies() const
{
    std::vector<std::shared_ptr<Policy>> result;

    for (const auto& [name, policy] : policies_)
    {
        if (policy && policy->isReady())
        {
            result.push_back(policy);
        }
    }

    return result;
}

std::vector<std::shared_ptr<Policy>> PolicyManager::getAllPolicies() const
{
    std::vector<std::shared_ptr<Policy>> result;

    for (const auto& [name, policy] : policies_)
    {
        result.push_back(policy);
    }

    return result;
}

void PolicyManager::loadPolicies()
{
    policies_.clear();

    for (size_t i = 0; i < db_.size(); i++)
    {
        const auto& row = db_.getRow(i);
        Policy policy = Policy::fromRow(row);
        policies_[policy.name] = std::make_shared<Policy>(policy);
    }
}

bool PolicyManager::updatePolicy(const std::string& name, const Policy& policy)
{
    for (size_t i = 0; i < db_.size(); i++)
    {
        const auto& row = db_.getRow(i);
        if (row.size() >= 1)
        {
            auto rowName = getFieldValue<std::string>(row[0]);
            if (rowName == name)
            {
                return db_.updateRow(i, policy.toRow());
            }
        }
    }
    return false;
}

} // namespace snet::pki