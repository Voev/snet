#pragma once
#include <casket/server/generic_server.hpp>
#include <casket/utils/string.hpp>
#include <casket/nonstd/optional.hpp>

#include <snet/pki/cert_manager.hpp>
#include <snet/pki/policy_manager.hpp>

#include <snet/crypto/cert.hpp>
#include <snet/crypto/cert_authority.hpp>
#include <snet/crypto/asymm_key.hpp>
#include <snet/crypto/cert_request.hpp>
#include <snet/crypto/rsa_asymm_key.hpp>
#include <snet/crypto/bio.hpp>

namespace snet::pki
{

struct PKIManagerCommand
{
    std::string command;
    std::string args;

    casket::PackResult<casket::Packer*> pack(casket::Packer& packer) const
    {
        auto res = packer.packMapStart(2);
        if (!res)
            return casket::PackResult<casket::Packer*>(res.error());

        res = packer.pack("cmd");
        if (!res)
            return casket::PackResult<casket::Packer*>(res.error());

        res = packer.pack(command);
        if (!res)
            return casket::PackResult<casket::Packer*>(res.error());

        res = packer.pack("args");
        if (!res)
            return casket::PackResult<casket::Packer*>(res.error());

        res = packer.pack(args);
        if (!res)
            return casket::PackResult<casket::Packer*>(res.error());

        return casket::PackResult<casket::Packer*>(&packer);
    }

    static casket::UnpackResult<PKIManagerCommand> unpack(casket::Unpacker& unpacker)
    {
        auto mapSizeResult = unpacker.unpackMapSize();
        if (!mapSizeResult)
            return casket::UnpackResult<PKIManagerCommand>(mapSizeResult.error());

        size_t mapSize = *mapSizeResult;
        PKIManagerCommand request;

        for (size_t i = 0; i < mapSize; ++i)
        {
            auto keyResult = unpacker.unpackString();
            if (!keyResult)
                return casket::UnpackResult<PKIManagerCommand>(keyResult.error());

            std::string_view key = *keyResult;

            if (key == "cmd")
            {
                auto valueResult = unpacker.unpackString();
                if (!valueResult)
                    return casket::UnpackResult<PKIManagerCommand>(valueResult.error());
                request.command = *valueResult;
            }
            else if (key == "args")
            {
                auto valueResult = unpacker.unpackString();
                if (!valueResult)
                    return casket::UnpackResult<PKIManagerCommand>(valueResult.error());
                request.args = *valueResult;
            }
            else
            {
                auto skipResult = unpacker.unpackString();
                if (!skipResult)
                    return casket::UnpackResult<PKIManagerCommand>(skipResult.error());
            }
        }

        return casket::UnpackResult<PKIManagerCommand>(request);
    }
};

struct PKIManagerResponse
{
    std::string retcode;
    nonstd::optional<std::string> body;

    casket::PackResult<casket::Packer*> pack(casket::Packer& packer) const
    {
        auto res = packer.packMapStart(1);
        if (!res)
            return casket::PackResult<casket::Packer*>(res.error());

        res = packer.pack("retcode");
        if (!res)
            return casket::PackResult<casket::Packer*>(res.error());

        res = packer.pack(retcode);
        if (!res)
            return casket::PackResult<casket::Packer*>(res.error());

        return casket::PackResult<casket::Packer*>(&packer);
    }

    static casket::UnpackResult<PKIManagerResponse> unpack(casket::Unpacker& unpacker)
    {
        auto mapSizeResult = unpacker.unpackMapSize();
        if (!mapSizeResult)
            return casket::UnpackResult<PKIManagerResponse>(mapSizeResult.error());

        size_t mapSize = *mapSizeResult;
        PKIManagerResponse resp;

        for (size_t i = 0; i < mapSize; ++i)
        {
            auto keyResult = unpacker.unpackString();
            if (!keyResult)
                return casket::UnpackResult<PKIManagerResponse>(keyResult.error());

            std::string_view key = *keyResult;

            if (key == "retcode")
            {
                auto valueResult = unpacker.unpackString();
                if (!valueResult)
                    return casket::UnpackResult<PKIManagerResponse>(valueResult.error());
                resp.retcode = *valueResult;
            }
            else
            {
                auto skipResult = unpacker.unpackString();
                if (!skipResult)
                    return casket::UnpackResult<PKIManagerResponse>(skipResult.error());
            }
        }

        return casket::UnpackResult<PKIManagerResponse>(resp);
    }
};

class PKIManager
{
public:
    explicit PKIManager(const std::string& storageDir);

    std::shared_ptr<Policy> getPolicy(const std::string& name) const
    {
        return policyManager_->getPolicy(name);
    }

    bool addPolicy(const std::string& name, std::shared_ptr<Policy> policy);
    bool removePolicy(const std::string& name);

    std::string handleHelp()
    {
        return "Commands:\n"
               "  create-policy <name>                 - Create a new policy with name\n"
               "  gen-key <name>                       - Generate private key for policy\n"
               "  gen-ss-cert <name>                   - Generate self-signed certificate for policy\n"
               "  info-policy <name>                   - Print information about existing policy\n"
               "  add-policy <name> <ca_cert> <ca_key> - Add new policy\n"
               "  rm-policy <name>                     - Remove existing policy\n"
               "  help                                 - Show this help";
    }

    std::string handlePolicyInfo(const std::string& name)
    {
        auto policy = getPolicy(name);
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

    std::string handleResign(const std::string& name, const std::string& base64Cert, const std::string& base64PublicKey)
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
                std::cout << "GOT CACHED!" << std::endl;
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
            std::string err = "ERROR: Failed to sign request with profile '" + name + "': ";
            return err + e.what();
        }
    }

    std::string handleCreatePolicy(const std::string& name)
    {
        try
        {
            if (!policyManager_->createPolicy(name))
            {
                return "ERROR: " + policyManager_->getLastError();
            }
            return "OK: policy '" + name + "' was created successfully";
        }
        catch (const std::exception& e)
        {
            return e.what();
        }
    }

    std::string handleGenerateKey(const std::string& name)
    {
        try
        {
            // Проверяем существование политики
            if (!policyManager_->hasPolicy(name))
            {
                return "ERROR: policy '" + name + "' not found";
            }

            // Получаем путь к ключу
            auto keyPath = policyManager_->getDefaultKeyPath(name);

            // Проверяем, не существует ли уже ключ
            if (std::filesystem::exists(keyPath))
            {
                return "ERROR: private key already exists for policy '" + name + "' at: " + keyPath;
            }

            // Генерируем ключевую пару
            auto key = crypto::RsaAsymmKey::generate(2048, false);

            // Сохраняем ключ в файл
            auto filename = crypto::BioTraits::openFile(keyPath, "wb");
            if (!filename)
            {
                return "ERROR: failed to open file for writing: " + keyPath;
            }

            crypto::AsymmKey::toBio(KeyType::Private, key, filename, Encoding::PEM);

            // Добавляем ключ к политике
            if (!policyManager_->addKeyToPolicy(name, keyPath))
            {
                // В случае ошибки удаляем созданный файл
                std::error_code ec;
                std::filesystem::remove(keyPath, ec);
                return "ERROR: failed to add key to policy: " + policyManager_->getLastError();
            }

            return "OK: private key successfully generated for policy '" + name + "' at: " + keyPath;
        }
        catch (const std::filesystem::filesystem_error& e)
        {
            return "ERROR: filesystem error for policy '" + name + "': " + e.what();
        }
        catch (const std::exception& e)
        {
            return "ERROR: failed to generate private key for policy '" + name + "': " + e.what();
        }
    }

    std::string handleGenerateSelfSignedCert(const std::string& name, const std::string& certDn)
    {
        try
        {
            // Проверяем существование политики
            auto policy = policyManager_->getPolicy(name);
            if (!policy)
            {
                return "ERROR: Policy '" + name + "' not found";
            }

            // Проверяем, не существует ли уже сертификат
            if (!policy->caCertPath.empty())
            {
                return "ERROR: certificate already set for policy '" + name + "' at: " + policy->caCertPath;
            }

            // Проверяем наличие ключа
            if (policy->caKeyPath.empty())
            {
                return "ERROR: private key not found for policy '" + name + "'. Generate key first.";
            }

            // Проверяем существование файла ключа
            if (!std::filesystem::exists(policy->caKeyPath))
            {
                return "ERROR: private key file not found: " + policy->caKeyPath;
            }

            // Проверяем существование директории политики
            if (!policyManager_->hasPolicyDirectory(name))
            {
                if (!policyManager_->createPolicyDirectory(name))
                {
                    return "ERROR: failed to create policy directory: " + policyManager_->getLastError();
                }
            }

            // Используем стандартный путь для сертификата
            auto certificatePath = policyManager_->getDefaultCertPath(name);

            // Проверяем, не существует ли уже файл сертификата
            if (std::filesystem::exists(certificatePath))
            {
                return "ERROR: certificate file already exists: " + certificatePath;
            }

            // Загружаем приватный ключ
            auto key = crypto::AsymmKey::fromStorage(KeyType::Private, policy->caKeyPath);
            if (!key)
            {
                return "ERROR: failed to load private key from: " + policy->caKeyPath;
            }

            // Создаем CA entity
            auto entity = std::make_shared<crypto::CertAuthority>(std::move(key), certDn);
            entities_[name] = entity;

            // Сохраняем сертификат в файл
            auto filename = crypto::BioTraits::openFile(certificatePath, "wb");
            if (!filename)
            {
                return "ERROR: failed to open file for writing: " + certificatePath;
            }

            crypto::Cert::toBio(entity->getCert(), filename, Encoding::PEM);

            // Добавляем сертификат к политике
            if (!policyManager_->addCertificateToPolicy(name, certificatePath))
            {
                // В случае ошибки удаляем созданный файл
                std::error_code ec;
                std::filesystem::remove(certificatePath, ec);
                return "ERROR: failed to add certificate to policy: " + policyManager_->getLastError();
            }

            // Сохраняем изменения
            if (!policyManager_->savePolicies())
            {
                return "ERROR: failed to save policies: " + policyManager_->getLastError();
            }

            return "OK: self-signed certificate successfully generated for policy '" + name +
                   "' at: " + certificatePath;
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

    /*std::string handleGenerateCertRequest(const std::string& name, const std::string& certDn)
    {
        try
        {
            auto policy = getPolicy(name);
            if (!policy)
            {
                return "ERROR: Policy '" + name + "' not found";
            }

            if (!policy->caCertPath.empty())
            {
                return "ERROR: certificate already setted for '" + name + "'";
            }

            std::filesystem::path p = policyManager_->storage();
            p /= name;

            std::filesystem::path certificatePath = p / "certificate.pem";
            policy->caCertPath = certificatePath.string();

            auto key = crypto::AsymmKey::fromStorage(KeyType::Private, policy->caKeyPath);
            auto entity = std::make_shared<crypto::CertAuthority>(std::move(key), certDn);

            auto filename = crypto::BioTraits::openFile(policy->caCertPath, "wb");
            crypto::Cert::toBio(entity->getCert(), filename, Encoding::PEM);

            policyManager_->savePolicies();

            return "OK: self-signed certificate successfully generated for policy '" + name + "'";
        }
        catch (const std::exception& e)
        {
            std::string err = "ERROR: failed to generate self-signed certificate for policy '" + name + "': ";
            return err + e.what();
        }
    }*/

    std::string handleRemovePolicy(const std::string& name)
    {
        try
        {
            if (!policyManager_->hasPolicy(name))
            {
                return "ERROR: Policy '" + name + "' not found";
            }

            auto policy = policyManager_->getPolicy(name);
            if (policy && policy->isActive())
            {
                return "ERROR: Cannot remove active policy '" + name + "'. Deactivate it first.";
            }

            auto policyPath = policyManager_->getPolicyPath(name);

            if (!policyManager_->removePolicy(name))
            {
                return "ERROR: Failed to remove policy '" + name + "': " + policyManager_->getLastError();
            }

            std::string result = "OK: Policy '" + name + "' removed successfully";

            if (!std::filesystem::exists(policyPath))
            {
                result += " (directory removed)";
            }

            return result;
        }
        catch (const std::exception& e)
        {
            return "ERROR: failed to remove policy '" + name + "': " + e.what();
        }
    }

    bool processCommand(casket::Context<casket::UnixSocket>& ctx)
    {
        std::error_code ec{};
        PKIManagerResponse resp{};

        auto req = ctx.readThenUnpack<PKIManagerCommand>(ec);

        if (req.has_value())
        {
            if (req.value().command == "create-policy")
            {
                if (req.value().args.empty())
                {
                    resp.retcode = "ERROR: invalid parameters";
                }
                else
                {
                    auto tokens = casket::split(req.value().args, " ");
                    if (tokens.size() != 1)
                    {
                        resp.retcode = "ERROR: invalid count of parameters";
                    }
                    else
                    {
                        resp.retcode = handleCreatePolicy(tokens[0]);
                    }
                }
            }
            else if (req.value().command == "gen-key")
            {
                if (req.value().args.empty())
                {
                    resp.retcode = "ERROR: invalid parameters";
                }
                else
                {
                    auto tokens = casket::split(req.value().args, " ");
                    if (tokens.size() != 1)
                    {
                        resp.retcode = "ERROR: invalid count of parameters";
                    }
                    else
                    {
                        resp.retcode = handleGenerateKey(tokens[0]);
                    }
                }
            }
            else if (req.value().command == "gen-ss-cert")
            {
                if (req.value().args.empty())
                {
                    resp.retcode = "ERROR: invalid parameters";
                }
                else
                {
                    auto tokens = casket::split(req.value().args, " ");
                    if (tokens.size() != 2)
                    {
                        resp.retcode = "ERROR: invalid count of parameters";
                    }
                    else
                    {
                        resp.retcode = handleGenerateSelfSignedCert(tokens[0], tokens[1]);
                    }
                }
            }
            else if (req.value().command == "rm-policy")
            {
                if (req.value().args.empty())
                {
                    resp.retcode = "ERROR: invalid parameters";
                }
                else
                {
                    auto tokens = casket::split(req.value().args, " ");
                    if (tokens.size() != 1)
                    {
                        resp.retcode = "ERROR: invalid count of parameters";
                    }
                    else
                    {
                        resp.retcode = handleRemovePolicy(tokens[0]);
                    }
                }
            }
            else if (req.value().command == "info-policy")
            {
                if (req.value().args.empty())
                {
                    resp.retcode = "ERROR: invalid parameters";
                }
                else
                {
                    auto tokens = casket::split(req.value().args, " ");
                    if (tokens.size() != 1)
                    {
                        resp.retcode = "ERROR: invalid count of parameters";
                    }
                    else
                    {
                        resp.retcode = handlePolicyInfo(tokens[0]);
                    }
                }
            }
            else if (req.value().command == "sign-csr")
            {
                if (req.value().args.empty())
                {
                    resp.retcode = "ERROR: invalid parameters";
                }
                else
                {
                    auto tokens = casket::split(req.value().args, " ");
                    if (tokens.size() != 3)
                    {
                        resp.retcode = "ERROR: invalid count of parameters";
                    }
                    else
                    {
                        resp.retcode = handleResign(tokens[0], tokens[1], tokens[2]);
                    }
                }
            }
            else if (req.value().command == "help" || req.value().command == "?")
            {
                resp.retcode = handleHelp();
            }
        }
        else
        {
            resp.retcode = "ERROR: Unknown command. Type 'help' for available commands";
        }

        return ctx.packThenSend<PKIManagerResponse>(resp, ec);
    }

private:
    std::string storageDir_;
    std::unique_ptr<PolicyManager> policyManager_;
    std::unique_ptr<CertManager> certManager_;
    std::map<std::string, std::shared_ptr<crypto::CertAuthority>> entities_;
};

} // namespace snet::pki