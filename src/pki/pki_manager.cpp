#include <snet/pki/pki_manager.hpp>

namespace snet::pki
{

PKIManager::PKIManager(const std::string& storageDir)
    : storageDir_(storageDir)
    , policyManager_(std::make_unique<PolicyManager>(storageDir_))
    , certManager_(std::make_unique<CertManager>(*policyManager_, storageDir_))
{
    auto policies = policyManager_->getActivePolicies();
    for (const auto& policy : policies)
    {
        auto key = crypto::AsymmKey::fromStorage(KeyType::Private, policy->caKeyPath);
        auto cert = crypto::Cert::fromStorage(policy->caCertPath);

        auto entity = std::make_shared<crypto::CertAuthority>(std::move(key), std::move(cert));
        entities_[policy->name] = entity;
    }
}

} // namespace snet::pki