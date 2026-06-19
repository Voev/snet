#pragma once
#include <casket/server/generic_server.hpp>
#include <casket/utils/string.hpp>
#include <casket/nonstd/optional.hpp>

#include <snet/pki/storage_config.hpp>
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
    explicit PKIManager(const StorageConfig& storageDir);

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

    std::string handleCreatePolicy(const std::string& name);

    std::string handleRemovePolicy(const std::string& name);

    std::string handleEnablePolicy(const std::string& name);

    std::string handleDisablePolicy(const std::string& name);

    std::string handlePolicyInfo(const std::string& name);

    std::string handleGenerateKey(const std::string& name);

    std::string handleGenerateSelfSignedCert(const std::string& name, const std::string& certDn);

    std::string handleResign(const std::string& name, const std::string& base64Cert,
                             const std::string& base64PublicKey);

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
            else if (req.value().command == "enable-policy")
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
                        resp.retcode = handleEnablePolicy(tokens[0]);
                    }
                }
            }
            else if (req.value().command == "disable-policy")
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
                        resp.retcode = handleDisablePolicy(tokens[0]);
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
    void loadEntity(const std::shared_ptr<Policy>& policy);

    void unloadEntity(const std::string& name);

private:
    const StorageConfig& storageConfig_;
    std::unique_ptr<PolicyManager> policyManager_;
    std::unique_ptr<CertManager> certManager_;
    std::map<std::string, std::shared_ptr<crypto::CertAuthority>> entities_;
};

} // namespace snet::pki