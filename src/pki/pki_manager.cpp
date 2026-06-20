#include <snet/pki/pki_manager.hpp>

namespace snet::pki
{

PKIManager::PKIManager(const StorageConfig& storageConfig)
    : storageConfig_(storageConfig)
    , policyManager_(std::make_unique<PolicyManager>(storageConfig))
    , certManager_(std::make_unique<CertManager>(storageConfig))
{
    registerCommands();

    auto policies = policyManager_->getReadyPolicies();
    for (const auto& policy : policies)
    {
        loadEntity(policy);
    }
}

CommandResult<std::string> PKIManager::handleHelp()
{
    std::ostringstream oss;
    dispatcher_.printCommands(oss);
    return success(oss.str());
}

CommandResult<std::string> PKIManager::handleCreatePolicy(const std::string& name)
{
    try
    {
        policyManager_->createPolicy(name);
        return success("OK: policy '" + name + "' was created successfully");
    }
    catch (const std::exception& e)
    {
        return error("ERROR: failed to create policy '" + name + "': " + std::string(e.what()));
    }
}

CommandResult<std::string> PKIManager::handleRemovePolicy(const std::string& name)
{
    try
    {
        policyManager_->removePolicy(name);
        return success("OK: policy '" + name + "' successfully removed");
    }
    catch (const std::exception& e)
    {
        return error("ERROR: failed to remove policy '" + name + "': " + e.what());
    }
}

CommandResult<std::string> PKIManager::handleEnablePolicy(const std::string& name)
{
    try
    {
        auto policy = policyManager_->getPolicy(name);
        casket::ThrowIfTrue(policy == nullptr, "policy '{}' does not exist", name);

        /// @todo: use action chain
        loadEntity(policy);

        policyManager_->enablePolicy(policy);
        return success("OK: policy '" + name + "' successfully enabled");
    }
    catch (const std::exception& e)
    {
        return error("ERROR: failed to enable policy '" + name + "': " + e.what());
    }
}

CommandResult<std::string> PKIManager::handleDisablePolicy(const std::string& name)
{
    try
    {
        auto policy = policyManager_->getPolicy(name);
        casket::ThrowIfTrue(policy == nullptr, "policy '{}' does not exist", name);

        /// @todo: use action chain
        unloadEntity(name);

        policyManager_->disablePolicy(policy);
        return success("OK: policy '" + name + "' successfully removed");
    }
    catch (const std::exception& e)
    {
        return error("ERROR: failed to disable policy '" + name + "': " + e.what());
    }
}

CommandResult<std::string> PKIManager::handlePolicyInfo(const std::string& name)
{
    try
    {
        auto policy = policyManager_->getPolicy(name);
        casket::ThrowIfTrue(policy == nullptr, "policy does not exist");

        std::ostringstream response;
        response << "Policy: " << name << "\n";
        response << "  CA Certificate: " << policy->caCertPath << "\n";
        response << "  CA Key: " << policy->caKeyPath << "\n";
        return success(response.str());
    }
    catch (const std::exception& e)
    {
        return error("ERROR: failed to handle policy '" + name + "': " + e.what());
    }
}

CommandResult<std::string> PKIManager::handleGenerateKey(const std::string& name)
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

        return success("OK: private key successfully generated for policy '" + name + "' at: " + keyPath);
    }
    catch (const std::exception& e)
    {
        return error("ERROR: policy '" + name + "': " + e.what());
    }
}

CommandResult<std::string> PKIManager::handleGenerateSelfSignedCert(const std::string& name, const std::string& certDn)
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
        /// @todo: does we need to auto enabling policy?
        auto entity = std::make_shared<crypto::CertAuthority>(std::move(key), certDn);
        entities_[name] = entity;

        auto filename = crypto::BioTraits::openFile(certPath, "wb");
        crypto::Cert::toBio(entity->getCert(), filename, Encoding::PEM);

        policyManager_->addCertificateToPolicy(policy, certPath);

        return success("OK: self-signed certificate successfully generated for policy '" + name + "' at: " + certPath);
    }
    catch (const std::exception& e)
    {
        return error("ERROR: failed to generate self-signed certificate for policy '" + name + "': " + e.what());
    }
}

CommandResult<std::string> PKIManager::handleResign(const std::string& name, const std::string& base64Cert,
                                                    const std::string& base64PublicKey)
{
    try
    {
        auto policy = policyManager_->getPolicy(name);
        casket::ThrowIfTrue(policy == nullptr, "policy '{}' does not exist", name);

        auto cert = crypto::Cert::fromBase64(base64Cert);
        auto fingerprint = CertFingerprintGenerator::generate(cert, EVP_sha1());

        auto resignedCert = certManager_->findByFingerprint(fingerprint, SteadyClock::now());
        if (resignedCert)
        {
            return success(crypto::Cert::toBase64(resignedCert));
        }

        auto ca = entities_.find(name);
        if (ca == entities_.end())
        {
            return error("ERROR: not found entity");
        }

        auto publicKey = crypto::AsymmKey::fromBase64(KeyType::Public, base64PublicKey);

        auto res = ca->second->resign(publicKey, cert);
        auto base64Result = crypto::Cert::toBase64(res);

        certManager_->insertCertificate(name, fingerprint, res);

        return success(std::move(base64Result));
    }
    catch (const std::exception& e)
    {
        return error("ERROR: Failed to sign request with policy '" + name + "': " + e.what());
    }
}

void PKIManager::registerCommands()
{
    dispatcher_.registerCommand("help",
                                "Show this help",
                                [this](const std::vector<std::string>& args) -> CommandResult<std::string>
                                {
                                    (void)args;
                                    return handleHelp();
                                });

    dispatcher_.registerCommand("create-policy",
                                "Create a new policy with name",
                                [this](const std::vector<std::string>& args) -> CommandResult<std::string>
                                {
                                    if (args.size() != 1 || args[0].empty())
                                    {
                                        return CommandResult<std::string>("Usage: create-policy <name>");
                                    }
                                    return handleCreatePolicy(args[0]);
                                });

    dispatcher_.registerCommand("rm-policy",
                                "Remove existing policy",
                                [this](const std::vector<std::string>& args) -> CommandResult<std::string>
                                {
                                    if (args.size() != 1 || args[0].empty())
                                    {
                                        return CommandResult<std::string>("Usage: rm-policy <name>");
                                    }
                                    return handleRemovePolicy(args[0]);
                                });

    dispatcher_.registerCommand("info-policy",
                                "Print information about policy",
                                [this](const std::vector<std::string>& args) -> CommandResult<std::string>
                                {
                                    if (args.size() != 1 || args[0].empty())
                                    {
                                        return CommandResult<std::string>("Usage: info-policy <name>");
                                    }
                                    return handlePolicyInfo(args[0]);
                                });

    dispatcher_.registerCommand("enable-policy",
                                "Enable existing policy",
                                [this](const std::vector<std::string>& args) -> CommandResult<std::string>
                                {
                                    if (args.size() != 1 || args[0].empty())
                                    {
                                        return CommandResult<std::string>("Usage: enable-policy <name>");
                                    }
                                    return handleEnablePolicy(args[0]);
                                });

    dispatcher_.registerCommand("disable-policy",
                                "Disable existing policy",
                                [this](const std::vector<std::string>& args) -> CommandResult<std::string>
                                {
                                    if (args.size() != 1 || args[0].empty())
                                    {
                                        return CommandResult<std::string>("Usage: disable-policy <name>");
                                    }
                                    return handleDisablePolicy(args[0]);
                                });

    dispatcher_.registerCommand("gen-key",
                                "Generate private key for policy",
                                [this](const std::vector<std::string>& args) -> CommandResult<std::string>
                                {
                                    if (args.size() != 1 || args[0].empty())
                                    {
                                        return CommandResult<std::string>("Usage: gen-key <name>");
                                    }
                                    return handleGenerateKey(args[0]);
                                });

    dispatcher_.registerCommand("gen-ss-cert",
                                "Generate self-signed certificate",
                                [this](const std::vector<std::string>& args) -> CommandResult<std::string>
                                {
                                    if (args.size() != 2 || args[0].empty() || args[1].empty())
                                    {
                                        return CommandResult<std::string>("Usage: gen-ss-cert <name> <cert_dn>");
                                    }
                                    return handleGenerateSelfSignedCert(args[0], args[1]);
                                });
}

bool PKIManager::processCommand(casket::Context<casket::UnixSocket>& ctx)
{
    std::error_code ec{};
    PKIManagerResponse resp{};

    auto req = ctx.readThenUnpack<PKIManagerCommand>(ec);

    if (!req.has_value())
    {
        resp.retcode = "ERROR: " + CommandError(CommandErrorCode::InvalidArguments).toString();
        return ctx.packThenSend<PKIManagerResponse>(resp, ec);
    }

    std::vector<std::string> args;
    if (!req.value().args.empty())
    {
        args = casket::split(req.value().args, " ");
    }

    auto result = dispatcher_.execute(req.value().command, args);

    if (result.has_value())
    {
        resp.retcode = result.value();
    }
    else
    {
        const auto& err = result.error();
        if (!err.message.empty())
        {
            resp.retcode = "ERROR: " + err.message;
        }
        else
        {
            resp.retcode = "ERROR: " + err.codeToString();
        }
    }

    return ctx.packThenSend<PKIManagerResponse>(resp, ec);
}

void PKIManager::loadEntity(const std::shared_ptr<Policy>& policy)
{
    auto key = crypto::AsymmKey::fromStorage(KeyType::Private, policy->caKeyPath);
    auto cert = crypto::Cert::fromStorage(policy->caCertPath);

    auto entity = std::make_shared<crypto::CertAuthority>(std::move(key), std::move(cert));
    entities_[policy->name] = entity;
}

void PKIManager::unloadEntity(const std::string& name)
{
    entities_.erase(name);
}

} // namespace snet::pki