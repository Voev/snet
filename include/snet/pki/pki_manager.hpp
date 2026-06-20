#pragma once
#include <casket/server/generic_server.hpp>
#include <casket/utils/string.hpp>
#include <casket/nonstd/optional.hpp>

#include <snet/pki/pki_cmd_dispatcher.hpp>
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

    CommandResult<std::string> handleHelp();

    CommandResult<std::string> handleCreatePolicy(const std::string& name);

    CommandResult<std::string> handleRemovePolicy(const std::string& name);

    CommandResult<std::string> handleEnablePolicy(const std::string& name);

    CommandResult<std::string> handleDisablePolicy(const std::string& name);

    CommandResult<std::string> handlePolicyInfo(const std::string& name);

    CommandResult<std::string> handleGenerateKey(const std::string& name);

    CommandResult<std::string> handleGenerateSelfSignedCert(const std::string& name, const std::string& certDn);

    CommandResult<std::string> handleResign(const std::string& name, const std::string& base64Cert,
                                            const std::string& base64PublicKey);

    void registerCommands();

    bool processCommand(casket::Context<casket::UnixSocket>& ctx);

private:
    void loadEntity(const std::shared_ptr<Policy>& policy);

    void unloadEntity(const std::string& name);

private:
    const StorageConfig& storageConfig_;
    PKICommandDispatcher dispatcher_;
    std::unique_ptr<PolicyManager> policyManager_;
    std::unique_ptr<CertManager> certManager_;
    std::map<std::string, std::shared_ptr<crypto::CertAuthority>> entities_;
};

} // namespace snet::pki