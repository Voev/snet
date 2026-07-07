#include <snet/pki/policy_manager.hpp>

#include <casket/log/log.hpp>
#include <casket/utils/action_chain.hpp>
#include <casket/utils/exception.hpp>

#include <casket/db/txt/txt_database.hpp>
#include <casket/db/field_extractor.hpp>

using namespace casket;

namespace fs = std::filesystem;

namespace snet::pki
{

static inline std::vector<std::type_index> GetFieldTypes()
{
    return {
        typeid(std::string),  // name
        typeid(std::string),  // caCertPath
        typeid(std::string),  // caKeyPath
        typeid(std::uint32_t) // status
    };
}

Policy::Policy()
    : status(PolicyStatus::CREATED)
{
}

Policy::Policy(const std::string& n)
    : name(n)
    , status(PolicyStatus::CREATED)
{
}

bool Policy::hasKey() const
{
    return !caKeyPath.empty();
}

bool Policy::hasCertificate() const
{
    return !caCertPath.empty();
}

bool Policy::isComplete() const
{
    return hasKey() && hasCertificate();
}

bool Policy::isExpired() const
{
    return status == PolicyStatus::NOT_VALID;
}

bool Policy::isReady() const
{
    return status == PolicyStatus::ENABLED && isComplete();
}

bool Policy::canSign() const
{
    return isReady();
}

void Policy::updateStatus()
{
    if (status == PolicyStatus::DISABLED || status == PolicyStatus::NOT_VALID)
    {
        return;
    }

    bool hasKey = !caKeyPath.empty();
    bool hasCert = !caCertPath.empty();

    if (hasKey && hasCert)
    {
        if (status != PolicyStatus::ENABLED)
        {
            status = PolicyStatus::COMPLETE;
        }
    }
    else if (hasKey)
    {
        status = PolicyStatus::KEY_ADDED;
    }
    else
    {
        status = PolicyStatus::CREATED;
    }
}

void Policy::addKey(const std::string& keyPath)
{
    casket::ThrowIfTrue(!caKeyPath.empty(), "key already set");
    casket::ThrowIfTrue(status == PolicyStatus::ENABLED, "cannot add key to enabled policy");
    casket::ThrowIfTrue(status == PolicyStatus::DISABLED, "cannot add key to disabled policy");
    casket::ThrowIfTrue(status == PolicyStatus::NOT_VALID, "cannot add key to not valid policy");

    caKeyPath = keyPath;
    updateStatus(); // Becomes KEY_ADDED or COMPLETE (if cert exists)
}

void Policy::addCertificate(const std::string& certPath)
{
    casket::ThrowIfTrue(!caCertPath.empty(), "certificate already set");
    casket::ThrowIfTrue(status == PolicyStatus::ENABLED, "cannot add certificate to enabled policy");
    casket::ThrowIfTrue(status == PolicyStatus::DISABLED, "cannot add certificate to disabled policy");
    casket::ThrowIfTrue(status == PolicyStatus::NOT_VALID, "cannot add certificate to not valid policy");
    casket::ThrowIfTrue(!hasKey(), "cannot add certificate: key must be added first");

    caCertPath = certPath;
    // Now both key and cert present -> COMPLETE
    status = PolicyStatus::COMPLETE;
}

void Policy::enable()
{
    casket::ThrowIfTrue(status != PolicyStatus::COMPLETE, "cannot enable: policy must be COMPLETE");
    casket::ThrowIfTrue(!isComplete(), "cannot enable: policy must have both key and certificate");
    status = PolicyStatus::ENABLED;
}

void Policy::disable()
{
    casket::ThrowIfTrue(status != PolicyStatus::ENABLED && status != PolicyStatus::COMPLETE,
                        "cannot disable: policy must be ENABLED or COMPLETE");
    status = PolicyStatus::DISABLED;
}

void Policy::markNotValid()
{
    casket::ThrowIfTrue(status != PolicyStatus::ENABLED, "cannot mark not valid: policy must be ENABLED");
    status = PolicyStatus::NOT_VALID;
}

void Policy::restore()
{
    casket::ThrowIfTrue(status != PolicyStatus::DISABLED && status != PolicyStatus::NOT_VALID,
                        "cannot restore: policy must be DISABLED or NOT_VALID");

    // Restore based on available components
    if (isComplete())
    {
        status = PolicyStatus::COMPLETE;
    }
    else if (hasKey())
    {
        status = PolicyStatus::KEY_ADDED;
    }
    else
    {
        status = PolicyStatus::CREATED;
    }
}

nonstd::string_view Policy::statusToString(PolicyStatus status)
{
    switch (status)
    {
    case PolicyStatus::CREATED:
        return "CREATED - policy created, no components added";
    case PolicyStatus::KEY_ADDED:
        return "KEY_ADDED - private key added";
    case PolicyStatus::COMPLETE:
        return "COMPLETE - both key and certificate present";
    case PolicyStatus::ENABLED:
        return "ENABLED - policy is active and ready to use";
    case PolicyStatus::DISABLED:
        return "DISABLED - policy disabled, can not be used for signing";
    case PolicyStatus::NOT_VALID:
        return "NOT_VALID - certificate expired or invalid";
    default:
        return "UNKNOWN";
    }
}

void Policy::print(std::ostream& os) const
{
    os << "Policy: " << name << "\n";
    os << "  Status: " << statusToString(status) << "\n";
    os << "  CA Certificate: " << (caCertPath.empty() ? "not set" : caCertPath) << "\n";
    os << "  CA Key: " << (caKeyPath.empty() ? "not set" : caKeyPath) << "\n";
}

std::shared_ptr<casket::db::IRow> Policy::toRow() const
{
    auto row = std::make_shared<casket::db::TxtRow>(GetFieldTypes());
    row->setField(0, db::makeFieldValue(name));
    row->setField(1, db::makeFieldValue(caCertPath));
    row->setField(2, db::makeFieldValue(caKeyPath));
    row->setField(3, db::makeFieldValue(static_cast<std::uint32_t>(status)));
    return row;
}

Policy Policy::fromRow(const db::IRow& row)
{
    Policy policy;
    if (row.size() >= 4)
    {
        policy.name = db::extractField<std::string>(row, 0);
        policy.caCertPath = db::extractField<std::string>(row, 1);
        policy.caKeyPath = db::extractField<std::string>(row, 2);
        policy.status = static_cast<PolicyStatus>(db::extractField<uint32_t>(row, 3));
    }
    return policy;
}

static inline std::unique_ptr<db::IDatabase> CreateDatabase(const StorageConfig& config)
{
    auto metadataPath = config.getPolicyMetadataPath();
    auto db = std::make_unique<db::TxtDatabase>(GetFieldTypes());

    if (fs::exists(metadataPath))
    {
        db->readFromFile(metadataPath);
    }

    return db;
}

PolicyManager::PolicyManager(const StorageConfig& config)
    : config_(config)
    , db_(CreateDatabase(config))
{
    db_->createIndex(0);

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
            if (!db_->insert(policy->toRow()))
            {
                throw casket::RuntimeError(
                    "{} row: {}, field: {}", db_->getLastError(), db_->getErrorRow(), db_->getErrorField());
            }
        },
        [&]()
        {
            CSK_LOG_DEBUG("removing entry '%s'", name.c_str());

            auto fieldValue = db::makeFieldValue(name);
            const auto* foundRow = db_->findByIndex(0, fieldValue);
            if (foundRow)
            {
                for (size_t i = 0; i < db_->size(); ++i)
                {
                    if (&db_->getRow(i) == foundRow)
                    {
                        db_->remove(i);
                        break;
                    }
                }
            }
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
            db_->writeToFile(metadataPath);
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
            auto fieldValue = db::makeFieldValue(name);
            const auto* foundRow = db_->findByIndex(0, fieldValue);
            if (foundRow)
            {
                for (size_t i = 0; i < db_->size(); ++i)
                {
                    if (&db_->getRow(i) == foundRow)
                    {
                        db_->remove(i);
                        break;
                    }
                }
            }
        },
        [&]()
        {
            db_->insert(policyRow);
        });

    chain.addAction(
        [&]()
        {
            auto metadataPath = config_.getPolicyMetadataPath();
            db_->writeToFile(metadataPath);
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
            db_->writeToFile(metadataPath);
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
            db_->writeToFile(metadataPath);
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
            db_->writeToFile(metadataPath);
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
            db_->writeToFile(metadataPath);
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

    auto fieldValue = db::makeFieldValue(name);
    auto row = db_->findByIndex(0, fieldValue);
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

    for (size_t i = 0; i < db_->size(); i++)
    {
        const auto& row = db_->getRow(i);
        Policy policy = Policy::fromRow(row);
        policies_[policy.name] = std::make_shared<Policy>(policy);
    }
}

bool PolicyManager::updatePolicy(const std::string& name, const Policy& policy)
{
    auto row = policy.toRow();
    for (size_t i = 0; i < db_->size(); i++)
    {
        const auto& currentRow = db_->getRow(i);
        if (currentRow.size() >= 1)
        {
            auto rowName = db::extractField<std::string>(currentRow, 0);
            if (rowName == name)
            {
                return db_->update(i, *row);
            }
        }
    }
    return false;
}

} // namespace snet::pki