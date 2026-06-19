#include <snet/pki/pki_manager.hpp>

namespace snet::pki
{

PKIManager::PKIManager(const StorageConfig& storageConfig)
    : storageConfig_(storageConfig)
    , policyManager_(std::make_unique<PolicyManager>(storageConfig))
    , certManager_(std::make_unique<CertManager>(storageConfig))
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

std::string PKIManager::handleCreatePolicy(const std::string& name)
{
    try
    {
        policyManager_->createPolicy(name);
        return "OK: policy '" + name + "' was created successfully";
    }
    catch (const std::exception& e)
    {
        return "ERROR: " + std::string(e.what());
    }
}

std::string PKIManager::handleRemovePolicy(const std::string& name)
{
    try
    {
        policyManager_->removePolicy(name);
        return "OK: policy '" + name + "' successfully removed";
    }
    catch (const std::exception& e)
    {
        return "ERROR: failed to remove policy '" + name + "': " + e.what();
    }
}

std::string PKIManager::handlePolicyInfo(const std::string& name)
{
    auto policy = policyManager_->getPolicy(name);
    if (!policy)
    {
        return "ERROR: Policy '" + name + "' not found";
    }

    std::ostringstream response;
    response << "Policy: " << name << "\n";
    response << "  CA Certificate: " << policy->caCertPath << "\n";
    response << "  CA Key: " << policy->caKeyPath << "\n";
    return response.str();
}

std::string PKIManager::handleGenerateKey(const std::string& name)
{
    try
    {
        auto policy = policyManager_->getPolicy(name);
        casket::ThrowIfTrue(policy == nullptr, "policy '{}' does not exist", name);
        casket::ThrowIfTrue(!policy->caKeyPath.empty(), "key for policy '{}' already set", name);

        auto keyPath = storageConfig_.getCAKeyPath(name);

        /// @todo: fix this distortion
        try
        {
            crypto::AsymmKey::fromStorage(KeyType::Private, keyPath);
            throw casket::RuntimeError("key object already exists");
        }
        catch (const std::exception&)
        {
            // fallback: key does not exist
        }

        /// @todo: consistency for key file if addKeyToPolicy throws exception
        auto key = crypto::RsaAsymmKey::generate(2048, false);
        auto filename = crypto::BioTraits::openFile(keyPath, "wb");
        crypto::AsymmKey::toBio(KeyType::Private, key, filename, Encoding::PEM);

        policyManager_->addKeyToPolicy(policy, keyPath);

        return "OK: private key successfully generated for policy '" + name + "' at: " + keyPath;
    }
    catch (const std::filesystem::filesystem_error& e)
    {
        return "ERROR: filesystem error for policy '" + name + "': " + e.what();
    }
    catch (const std::exception& e)
    {
        return "ERROR: policy '" + name + "': " + e.what();
    }
}

std::string PKIManager::handleGenerateSelfSignedCert(const std::string& name, const std::string& certDn)
{
    try
    {
        auto policy = policyManager_->getPolicy(name);
        casket::ThrowIfTrue(policy == nullptr, "policy '{}' does not exist", name);
        casket::ThrowIfTrue(!policy->caCertPath.empty(), "certificate for policy '{}' already set", name);

        auto certPath = storageConfig_.getCACertPath(name);

        /// @todo: fix this distortion
        try
        {
            crypto::Cert::fromStorage(certPath);
            throw casket::RuntimeError("certificate object already exists");
        }
        catch (const std::exception&)
        {
            // fallback: certificate  does not exist
        }

        auto key = crypto::AsymmKey::fromStorage(KeyType::Private, policy->caKeyPath);

        /// @todo: consistency for cert file if throws exception
        auto entity = std::make_shared<crypto::CertAuthority>(std::move(key), certDn);
        entities_[name] = entity;

        auto filename = crypto::BioTraits::openFile(certPath, "wb");
        crypto::Cert::toBio(entity->getCert(), filename, Encoding::PEM);

        policyManager_->addCertificateToPolicy(policy, certPath);

        return "OK: self-signed certificate successfully generated for policy '" + name + "' at: " + certPath;
    }
    catch (const std::filesystem::filesystem_error& e)
    {
        return "ERROR: filesystem error for policy '" + name + "': " + e.what();
    }
    catch (const std::exception& e)
    {
        return "ERROR: failed to generate self-signed certificate for policy '" + name + "': " + e.what();
    }
}

std::string PKIManager::handleResign(const std::string& name, const std::string& base64Cert, const std::string& base64PublicKey)
{
    try
    {
        auto policy = policyManager_->getPolicy(name);
        if (!policy)
        {
            return "ERROR: Policy '" + name + "' not found";
        }

        auto cert = crypto::Cert::fromBase64(base64Cert);
        auto fingerprint = CertFingerprintGenerator::generate(cert, EVP_sha1());

        auto resignedCert = certManager_->findByFingerprint(fingerprint, SteadyClock::now());
        if (resignedCert)
        {
            return crypto::Cert::toBase64(resignedCert);
        }

        auto ca = entities_.find(name);
        if (ca == entities_.end())
        {
            return "ERROR: not found entity";
        }

        auto publicKey = crypto::AsymmKey::fromBase64(KeyType::Public, base64PublicKey);

        auto res = ca->second->resign(publicKey, cert);
        auto base64Result = crypto::Cert::toBase64(res);

        certManager_->insertCertificate(name, fingerprint, res);

        return base64Result;
    }
    catch (const std::exception& e)
    {
        std::string err = "ERROR: Failed to sign request with policy '" + name + "': ";
        return err + e.what();
    }
}

} // namespace snet::pki