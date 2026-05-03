#pragma once
#include <snet/pki/certificate_db.hpp>
#include <snet/pki/policy_manager.hpp>

#include <casket/server/generic_server.hpp>
#include <casket/utils/string.hpp>

#include <snet/crypto/cert.hpp>
#include <snet/crypto/cert_authority.hpp>
#include <snet/crypto/asymm_key.hpp>
#include <snet/crypto/cert_request.hpp>

namespace snet
{

struct CertificateInfo
{
    std::string serialNumber;
    std::string subject;
    std::string notBefore;
    std::string notAfter;
    std::string originalPath;
    std::string renewedPath;
};

struct CertManagerCommand
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

    static casket::UnpackResult<CertManagerCommand> unpack(casket::Unpacker& unpacker)
    {
        auto mapSizeResult = unpacker.unpackMapSize();
        if (!mapSizeResult)
            return casket::UnpackResult<CertManagerCommand>(mapSizeResult.error());

        size_t mapSize = *mapSizeResult;
        CertManagerCommand request;

        for (size_t i = 0; i < mapSize; ++i)
        {
            auto keyResult = unpacker.unpackString();
            if (!keyResult)
                return casket::UnpackResult<CertManagerCommand>(keyResult.error());

            std::string_view key = *keyResult;

            if (key == "cmd")
            {
                auto valueResult = unpacker.unpackString();
                if (!valueResult)
                    return casket::UnpackResult<CertManagerCommand>(valueResult.error());
                request.command = *valueResult;
            }
            else if (key == "args")
            {
                auto valueResult = unpacker.unpackString();
                if (!valueResult)
                    return casket::UnpackResult<CertManagerCommand>(valueResult.error());
                request.args = *valueResult;
            }
            else
            {
                auto skipResult = unpacker.unpackString();
                if (!skipResult)
                    return casket::UnpackResult<CertManagerCommand>(skipResult.error());
            }
        }

        return casket::UnpackResult<CertManagerCommand>(request);
    }
};

struct CertManagerResponse
{
    std::string retcode;

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

    static casket::UnpackResult<CertManagerResponse> unpack(casket::Unpacker& unpacker)
    {
        auto mapSizeResult = unpacker.unpackMapSize();
        if (!mapSizeResult)
            return casket::UnpackResult<CertManagerResponse>(mapSizeResult.error());

        size_t mapSize = *mapSizeResult;
        CertManagerResponse resp;

        for (size_t i = 0; i < mapSize; ++i)
        {
            auto keyResult = unpacker.unpackString();
            if (!keyResult)
                return casket::UnpackResult<CertManagerResponse>(keyResult.error());

            std::string_view key = *keyResult;

            if (key == "retcode")
            {
                auto valueResult = unpacker.unpackString();
                if (!valueResult)
                    return casket::UnpackResult<CertManagerResponse>(valueResult.error());
                resp.retcode = *valueResult;
            }
            else
            {
                auto skipResult = unpacker.unpackString();
                if (!skipResult)
                    return casket::UnpackResult<CertManagerResponse>(skipResult.error());
            }
        }

        return casket::UnpackResult<CertManagerResponse>(resp);
    }
};

class CertificateManager
{
public:
    explicit CertificateManager(const std::string& storageDir);

    bool initDatabase();
    bool databaseExists() const;

    std::shared_ptr<Policy> getPolicy(const std::string& name) const
    {
        return policyManager_->getPolicy(name);
    }

    bool addPolicy(const std::string& name, std::shared_ptr<Policy> policy);
    bool removePolicy(const std::string& name);

    std::string handleHelp()
    {
        return "Commands:\n"
               "  init                                 - Initialize database\n"
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

    std::string handleSignCsr(const std::string& name, const std::string& base64csr)
    {
        try
        {
            auto policy = getPolicy(name);
            if (!policy)
            {
                return "ERROR: Policy '" + name + "' not found";
            }

            auto ca = entities_.find(name);
            if (ca != entities_.end())
            {
                return "ERROR: not found entity";
            }

            auto csr = crypto::CertRequest::fromBase64(base64csr);
            (void)csr;

            return "OK";
        }
        catch (const std::exception& e)
        {
            std::string err = "ERROR: Failed to sign request with profile '" + name + "': ";
            return err + e.what();
        }
    }

    std::string handleAddPolicy(const std::string& name, const std::string& caCertPath, const std::string& caKeyPath)
    {
        try
        {
            auto cert = crypto::Cert::fromStorage(caCertPath);
            auto key = crypto::AsymmKey::fromStorage(KeyType::Private, caKeyPath);
            auto entity = std::make_shared<crypto::CertAuthority>(std::move(key), std::move(cert));

            auto policy = std::make_shared<Policy>();
            policy->caCertPath = caCertPath;
            policy->caKeyPath = caKeyPath;

            policyManager_->addPolicy(name, policy);
            entities_[name] = std::move(entity);

            return "OK: Policy '" + name + "' added and validated successfully";
        }
        catch (const std::exception& e)
        {
            std::string err = "ERROR: Failed to add profile '" + name + "': ";
            return err + e.what();
        }
    }

    std::string handleRemovePolicy(const std::string& name)
    {
        if (removePolicy(name))
        {
            return "OK: Policy '" + name + "' removed successfully";
        }
        else
        {
            return "ERROR: Policy '" + name + "' not found";
        }
    }

    bool processCommand(casket::Context<casket::UnixSocket>& ctx)
    {
        std::error_code ec{};
        CertManagerResponse resp{};

        auto req = ctx.readThenUnpack<CertManagerCommand>(ec);

        if (req.has_value())
        {
            if (req.value().command == "init")
            {
                auto result = initDatabase();
                resp.retcode = result ? "SUCCESS: database is initialized" : "ERROR: failed to init database";
            }
            else if (req.value().command == "add-policy")
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
                        resp.retcode = handleAddPolicy(tokens[0], tokens[1], tokens[2]);
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
                        auto tokens = casket::split(req.value().args, " ");
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
                        auto tokens = casket::split(req.value().args, " ");
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
                    if (tokens.size() != 2)
                    {
                        resp.retcode = "ERROR: invalid count of parameters";
                    }
                    else
                    {
                        auto tokens = casket::split(req.value().args, " ");
                        resp.retcode = handleSignCsr(tokens[0], tokens[1]);
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

        return ctx.packThenSend<CertManagerResponse>(resp, ec);
    }

private:
    std::string storageDir_;
    std::unique_ptr<PolicyManager> policyManager_;
    std::map<std::string, std::shared_ptr<crypto::CertAuthority>> entities_;
    std::unique_ptr<CertificateDb> certDatabase_;
};

} // namespace snet