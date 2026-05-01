#pragma once
#include <snet/pki/certificate_db.hpp>
#include <snet/pki/policy_manager.hpp>

#include <casket/server/generic_server.hpp>
#include <casket/utils/string.hpp>

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
               "  init                    - Initialize database\n"
               "  list-profiles           - List available renewal profiles\n"
               "  renew <cert> <profile>  - Renew certificate with specified profile\n"
               "  add-profile <name> <ca_cert> <ca_key> <days> - Add new profile\n"
               "  help                    - Show this help";
    }

    std::string handleProfileInfo(const std::string& name)
    {
        auto policy = getPolicy(name);
        if (!policy)
        {
            return "ERROR: Policy '" + name + "' not found";
        }

        std::ostringstream response;
        response << "Profile: " << name << "\n";
        response << "  CA Certificate: " << policy->caCertPath << "\n";
        response << "  CA Key: " << policy->caKeyPath << "\n";
        return response.str();
    }

    std::string handleAddProfile(const std::string& name, const std::string& caCertPath, const std::string& caKeyPath)
    {
        auto policy = std::make_shared<Policy>();

        policy->caKeyPath = caKeyPath;
        policy->caCertPath = caCertPath;

        if (addPolicy(name, policy))
        {
            return "OK: Profile '" + name + "' added and validated successfully";
        }
        else
        {
            return "ERROR: Failed to add profile '" + name + "'. Check certificate and key files";
        }
    }

    std::string handleRemoveProfile(const std::string& name)
    {
        if (removePolicy(name))
        {
            return "OK: Profile '" + name + "' removed successfully";
        }
        else
        {
            return "ERROR: Profile '" + name + "' not found";
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
            else if (req.value().command == "add-profile")
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
                        resp.retcode = handleAddProfile(tokens[0], tokens[1], tokens[2]);
                    }
                }
            }
            else if (req.value().command == "rm-profile")
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
                        resp.retcode = handleRemoveProfile(tokens[0]);
                    }
                }
            }
            else if (req.value().command == "info-profile")
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
                        resp.retcode = handleProfileInfo(tokens[0]);
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
    std::unique_ptr<CertificateDb> certDatabase_;
};

} // namespace snet