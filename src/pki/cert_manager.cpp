
#include <fstream>
#include <iostream>
#include <sstream>
#include <filesystem>
#include <chrono>
#include <random>
#include <iomanip>
#include <snet/pki/cert_manager.hpp>

namespace fs = std::filesystem;

namespace snet
{

CertificateManager::CertificateManager(const std::string& storageDir)
    : storageDir_(storageDir)
    , policyManager_(std::make_unique<PolicyManager>(storageDir_))
    , certDatabase_(std::make_unique<CertificateDb>(storageDir_, 1024, 4096))
{
}

bool CertificateManager::initDatabase()
{
    if (databaseExists())
    {
        fs::create_directories(storageDir_);
        return false;
    }

    policyManager_->clear();
    certDatabase_->create();

    return true;
}

bool CertificateManager::databaseExists() const
{
    return fs::exists(storageDir_);
}

bool CertificateManager::addPolicy(const std::string& name, std::shared_ptr<Policy> policy)
{
    return policyManager_->addPolicy(name, policy);
}

bool CertificateManager::removePolicy(const std::string& name)
{
    return policyManager_->removePolicy(name);
}

} // namespace snet