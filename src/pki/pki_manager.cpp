#include <snet/pki/pki_manager.hpp>
#include <snet/crypto/cert_req_builder.hpp>
#include <snet/crypto/group_params.hpp>
#include <snet/crypto/cert_self_signed.hpp>

#include <casket/utils/action_chain.hpp>

using namespace snet::crypto;
using namespace casket;

namespace
{

KeyPtr GeneratePrivateKey(const casket::json::Object& params)
{
    KeyPtr key;

    std::string alg = params.get<std::string>("alg").value();
    if (iequals(alg, "rsa"))
    {
        json::Integer rsaBits = params.getNested<json::Integer>(json::Path{"props", "rsa_bits"}).value();

        key = RsaAsymmKey::generate(static_cast<size_t>(rsaBits), false);
    }
    else if (iequals(alg, "ec"))
    {
        std::string ecCurve = params.getNested<std::string>(json::Path{"props", "ec_group"}).value();

        auto groupParams = GroupParams::fromString(ecCurve);
        casket::ThrowIfTrue(groupParams == GroupParams::Code::NONE, "unsupported group params");

        key = GroupParams::generateKeyByParams(groupParams);
    }
    else
    {
        throw std::runtime_error("unsupported algorithm: " + alg);
    }
    return key;
}

} // namespace

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

CommandResult<std::string> PKIManager::handleListPolicies()
{
    try
    {
        auto policies = policyManager_->getAllPolicies();

        std::ostringstream response;

        if (policies.empty())
        {
            response << "No policies found";
        }
        else
        {
            for (const auto& policy : policies)
            {
                policy->print(response);
            }
        }

        return success(response.str());
    }
    catch (const std::exception& e)
    {
        return error("ERROR: failed to list policies: " + std::string(e.what()));
    }
}

CommandResult<std::string> PKIManager::handlePolicyInfo(const json::Object& params)
{
    try
    {
        std::string name = params.get<std::string>("name").value();

        auto policy = policyManager_->getPolicy(name);
        casket::ThrowIfTrue(policy == nullptr, "policy does not exist");

        std::ostringstream response;
        policy->print(response);
        return success(response.str());
    }
    catch (const std::exception& e)
    {
        return error("ERROR: failed to handle policy info: " + std::string(e.what()));
    }
}

CommandResult<std::string> PKIManager::handleCreatePolicy(const json::Object& params)
{
    try
    {
        std::string name = params.get<std::string>("name").value();
        policyManager_->createPolicy(name);
        return success("OK: policy '" + name + "' was created successfully");
    }
    catch (const std::exception& e)
    {
        return error("ERROR: failed to create policy: " + std::string(e.what()));
    }
}

CommandResult<std::string> PKIManager::handleRemovePolicy(const json::Object& params)
{
    try
    {
        std::string name = params.get<std::string>("name").value();
        policyManager_->removePolicy(name);
        return success("OK: policy '" + name + "' successfully removed");
    }
    catch (const std::exception& e)
    {
        return error("ERROR: failed to remove policy: " + std::string(e.what()));
    }
}

CommandResult<std::string> PKIManager::handleEnablePolicy(const json::Object& params)
{
    try
    {
        std::string name = params.get<std::string>("name").value();

        auto policy = policyManager_->getPolicy(name);
        casket::ThrowIfTrue(policy == nullptr, "policy '{}' does not exist", name);

        casket::ActionChain chain;
        chain.addAction(
            [&]()
            {
                loadEntity(policy);
            },
            [&]()
            {
                unloadEntity(name);
            });
        chain.addAction(
            [&]()
            {
                policyManager_->enablePolicy(policy);
            });
        return success("OK: policy '" + name + "' successfully enabled");
    }
    catch (const std::exception& e)
    {
        return error("ERROR: failed to enable policy: " + std::string(e.what()));
    }
}

CommandResult<std::string> PKIManager::handleDisablePolicy(const json::Object& params)
{
    try
    {
        std::string name = params.get<std::string>("name").value();

        auto policy = policyManager_->getPolicy(name);
        casket::ThrowIfTrue(policy == nullptr, "policy '{}' does not exist", name);

        casket::ActionChain chain;
        chain.addAction(
            [&]()
            {
                unloadEntity(name);
            },
            [&]()
            {
                loadEntity(policy);
            });
        chain.addAction(
            [&]()
            {
                policyManager_->disablePolicy(policy);
            });
        chain.execute();
        return success("OK: policy '" + name + "' successfully removed");
    }
    catch (const std::exception& e)
    {
        return error("ERROR: failed to disable policy: " + std::string(e.what()));
    }
}

CommandResult<std::string> PKIManager::handleGenerateKey(const json::Object& params)
{
    try
    {
        std::string name = params.get<std::string>("name").value();

        auto policy = policyManager_->getPolicy(name);
        casket::ThrowIfTrue(policy == nullptr, "policy '{}' does not exist", name);
        casket::ThrowIfTrue(!policy->caKeyPath.empty(), "key for policy '{}' already set", name);

        /// @todo: make checkExist method.
        try
        {
            crypto::AsymmKey::fromStorage(KeyType::Private, policy->caKeyPath);
            throw casket::RuntimeError("key object already exists");
        }
        catch (const std::exception&)
        {
            // fallback: key does not exist
        }

        ActionChain chain;

        KeyPtr key;
        std::string keyPath = storageConfig_.getCAKeyPath(name);
        bool saveFile = params.getNested<bool>(json::Path{"props", "save_file"}).value();

        chain.addAction(
            [&]()
            {
                key = ::GeneratePrivateKey(params);

                if (saveFile)
                {
                    auto bio = crypto::BioTraits::openFile(keyPath, "wb");
                    crypto::AsymmKey::toBio(KeyType::Private, key, bio, Encoding::PEM);
                }
            },
            [&]()
            {
                if (saveFile)
                {
                    std::error_code ec;
                    std::filesystem::remove(keyPath, ec);
                }
            });

        chain.addAction(
            [&]()
            {
                policyManager_->addKeyToPolicy(policy, keyPath);
            });

        chain.execute();
        return success("OK: private key successfully generated for policy '" + name + "' at: " + keyPath);
    }
    catch (const std::exception& e)
    {
        return error("ERROR: failed to generate private key: " + std::string(e.what()));
    }
}

CommandResult<std::string> PKIManager::handleGenerateSelfSignedCert(const json::Object& params)
{
    try
    {
        std::string name = params.get<std::string>("name").value();

        auto policy = policyManager_->getPolicy(name);
        casket::ThrowIfTrue(policy == nullptr, "policy '{}' does not exist", name);
        casket::ThrowIfTrue(!policy->caCertPath.empty(), "certificate for policy '{}' already set", name);

        auto certPath = storageConfig_.getCACertPath(name);
        try
        {
            crypto::Cert::fromStorage(certPath);
            throw casket::RuntimeError("certificate object already exists");
        }
        catch (const std::exception&)
        {
            // fallback: certificate does not exist
        }

        X509CertPtr selfSignedCert;
        casket::ActionChain chain;
        chain.addAction(
            [&]()
            {
                std::string certDn = params.get<std::string>("cert_dn").value();
                json::Integer daysValidity = params.get<json::Integer>("cert_validity").value();
                auto key = crypto::AsymmKey::fromStorage(KeyType::Private, policy->caKeyPath);
                selfSignedCert = crypto::CertSelfSigned::generate(key, certDn, daysValidity);
            });
        chain.addAction(
            [&]()
            {
                auto filename = crypto::BioTraits::openFile(certPath, "wb");
                crypto::Cert::toBio(selfSignedCert, filename, Encoding::PEM);
            },
            [&]()
            {
                std::error_code ec;
                std::filesystem::remove(certPath, ec);
            });
        chain.addAction(
            [&]()
            {
                policyManager_->addCertificateToPolicy(policy, certPath);
            });
        chain.execute();
        return success("OK: self-signed certificate successfully generated for policy '" + name + "' at: " + certPath);
    }
    catch (const std::exception& e)
    {
        return error("ERROR: failed to generate self-signed certificate: " + std::string(e.what()));
    }
}

CommandResult<std::string> PKIManager::handleGetCertRequest(const json::Object& params)
{
    try
    {
        std::string name = params.get<std::string>("name").value();

        auto policy = policyManager_->getPolicy(name);
        casket::ThrowIfTrue(policy == nullptr, "policy '{}' does not exist", name);

        std::string csrDn = params.get<std::string>("csr_dn").value();
        auto key = AsymmKey::fromStorage(KeyType::Private, policy->caKeyPath);
        auto req = CertReqBuilder()
                       .signWith(key)
                       .setVersion(CertReqVersion::V1)
                       .setSubjectName(csrDn)
                       .setPublicKey(key)
                       .addExtension(NID_basic_constraints, "CA:TRUE,pathlen:0")
                       .addExtension(NID_key_usage, "keyCertSign,cRLSign")
                       .addExtension(NID_subject_key_identifier, "hash")
                       .build();

        return success(CertRequest::toBase64(req));
    }
    catch (const std::exception& e)
    {
        return error("ERROR: failed to get CSR: " + std::string(e.what()));
    }
}

CommandResult<std::string> PKIManager::handleResignCert(const json::Object& params)
{
    try
    {
        std::string name = params.get<std::string>("name").value();

        auto policy = policyManager_->getPolicy(name);
        casket::ThrowIfTrue(policy == nullptr, "policy '{}' does not exist", name);

        auto base64PublicKey = params.get<std::string>("subj_pubkey").value();
        auto base64Cert = params.get<std::string>("origin_cert").value();

        auto cert = crypto::Cert::fromBase64(base64Cert);
        auto fingerprint = CertFingerprintGenerator::generate(cert, EVP_sha1());

        /// Try to get the cached re-sgined certificated.
        auto resignedCert = certManager_->findByFingerprint(fingerprint, SteadyClock::now());
        if (resignedCert)
        {
            return success(crypto::Cert::toBase64(resignedCert));
        }

        auto ca = entities_.find(name);
        casket::ThrowIfTrue(ca == entities_.end(), "not found entity for policy '{}'", name);

        /// Re-sign a new certificate from the CA linked to the policy.s
        auto publicKey = crypto::AsymmKey::fromBase64(KeyType::Public, base64PublicKey);

        auto res = ca->second->resign(publicKey, cert);
        auto base64Result = crypto::Cert::toBase64(res);

        certManager_->insertCertificate(name, fingerprint, res);

        return success(std::move(base64Result));
    }
    catch (const std::exception& e)
    {
        return error("ERROR: Failed to re-sign certificate: " + std::string(e.what()));
    }
}

void PKIManager::registerCommands()
{
    dispatcher_.registerCommand("help",
                                "Show this help",
                                [&](const json::Value& params) -> CommandResult<std::string>
                                {
                                    (void)params;
                                    return handleHelp();
                                });

    dispatcher_.registerCommand("list-policies",
                                "List all existing policies",
                                [this](const json::Value& params) -> CommandResult<std::string>
                                {
                                    (void)params;
                                    return handleListPolicies();
                                });

    auto nameSchema = json::Schema::create();
    nameSchema->add(json::TypedParamSpec<std::string>("name", "Policy name", true));

    dispatcher_.registerCommand(
        "info-policy",
        "Print information about policy",
        [this](const json::Value& params) -> CommandResult<std::string>
        {
            const auto* obj = params.get<json::Object>();
            return handlePolicyInfo(*obj);
        },
        nameSchema);

    dispatcher_.registerCommand(
        "create-policy",
        "Create a new policy with name",
        [this](const json::Value& params) -> CommandResult<std::string>
        {
            const auto* obj = params.get<json::Object>();
            return handleCreatePolicy(*obj);
        },
        nameSchema);

    dispatcher_.registerCommand(
        "rm-policy",
        "Remove existing policy",
        [this](const json::Value& params) -> CommandResult<std::string>
        {
            const auto* obj = params.get<json::Object>();
            return handleRemovePolicy(*obj);
        },
        nameSchema);

    dispatcher_.registerCommand(
        "enable-policy",
        "Enable existing policy",
        [this](const json::Value& params) -> CommandResult<std::string>
        {
            const auto* obj = params.get<json::Object>();
            return handleEnablePolicy(*obj);
        },
        nameSchema);

    dispatcher_.registerCommand(
        "disable-policy",
        "Disable existing policy",
        [this](const json::Value& params) -> CommandResult<std::string>
        {
            const auto* obj = params.get<json::Object>();
            return handleDisablePolicy(*obj);
        },
        nameSchema);

    auto genKeySchema = json::Schema::create();
    genKeySchema->add(json::TypedParamSpec<std::string>("name", "Policy name", true));
    genKeySchema->add(json::TypedParamSpec<std::string>("alg", "Algorithm (rsa, ec, ed25519)", true)
                          .withAllowedValues({"rsa", "ec", "ed25519"}));
    genKeySchema->add(json::TypedParamSpec<json::Integer>("props.rsa_bits", "RSA key size in bits", false, 2048)
                          .withRange<json::Integer>(1024, 8192));
    genKeySchema->add(json::TypedParamSpec<std::string>("props.ec_curve", "EC curve name", false, "secp256r1")
                          .withAllowedValues({"secp256r1", "secp384r1", "secp521r1", "ed25519"}));
    genKeySchema->add(json::TypedParamSpec<bool>("props.save_file", "Output file path", true).withDefault(true));
    genKeySchema->add(json::TypedParamSpec<std::string>("protect.password", "Password for key protection", false));

    dispatcher_.registerCommand(
        "gen-key",
        "Generate private key for policy",
        [this](const json::Value& params) -> CommandResult<std::string>
        {
            const auto* obj = params.get<json::Object>();
            return handleGenerateKey(*obj);
        },
        genKeySchema);

    auto genSsCertSchema = json::Schema::create();
    genSsCertSchema->add(json::TypedParamSpec<std::string>("name", "Policy name", true));
    genSsCertSchema->add(json::TypedParamSpec<std::string>("cert_dn", "Certificate distinguished name", true));

    dispatcher_.registerCommand(
        "gen-ss-cert",
        "Generate self-signed certificate for CA policy",
        [this](const json::Value& params) -> CommandResult<std::string>
        {
            const auto* obj = params.get<json::Object>();
            return handleGenerateSelfSignedCert(*obj);
        },
        genSsCertSchema);

    auto getCsrSchema = json::Schema::create();
    getCsrSchema->add(json::TypedParamSpec<std::string>("name", "Policy name", true));
    getCsrSchema->add(json::TypedParamSpec<std::string>("csr_dn", "CSR distinguished name", true));

    dispatcher_.registerCommand(
        "get-csr",
        "Get certificate signing request (CSR) for policy",
        [this](const json::Value& params) -> CommandResult<std::string>
        {
            const auto* obj = params.get<json::Object>();
            return handleGetCertRequest(*obj);
        },
        genSsCertSchema);

    auto getResignCertSchema = json::Schema::create();
    getResignCertSchema->add(json::TypedParamSpec<std::string>("name", "Policy name", true));
    getResignCertSchema->add(json::TypedParamSpec<std::string>("subj_pubkey", "Subject public key", true));
    getResignCertSchema->add(
        json::TypedParamSpec<std::string>("origin_cert", "Origin certificate used as template", true));

    dispatcher_.registerCommand(
        "resign-cert",
        "Re-sign certificate with CA policy",
        [this](const json::Value& params) -> CommandResult<std::string>
        {
            const auto* obj = params.get<json::Object>();
            return handleResignCert(*obj);
        },
        getResignCertSchema);
}

bool PKIManager::processCommand(casket::Context<casket::UnixSocket>& ctx)
{
    std::error_code ec{};
    PKIManagerResponse resp{};

    auto req = ctx.readThenUnpack<PKIManagerCommand>(ec);

    if (!req.has_value())
    {
        resp.retcode = "ERROR: " + CommandError(CommandErrorCode::InvalidArguments).codeToString();
        return ctx.packThenSend<PKIManagerResponse>(resp, ec);
    }

    auto result = dispatcher_.execute(req.value().command, req.value().args);

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