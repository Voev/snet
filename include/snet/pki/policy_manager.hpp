#pragma once

#include <string>
#include <map>
#include <memory>
#include <vector>
#include <fstream>
#include <filesystem>
#include <casket/pack/pack.hpp>

namespace snet
{

struct Policy
{
    std::string caCertPath;
    std::string caKeyPath;

    ~Policy() = default;

    casket::PackResult<casket::Packer*> pack(casket::Packer& packer) const
    {
        auto res = packer.packMapStart(2);
        if (!res)
            return casket::PackResult<casket::Packer*>(res.error());

        res = packer.pack("caCertPath");
        if (!res)
            return casket::PackResult<casket::Packer*>(res.error());

        res = packer.pack(caCertPath);
        if (!res)
            return casket::PackResult<casket::Packer*>(res.error());

        res = packer.pack("caKeyPath");
        if (!res)
            return casket::PackResult<casket::Packer*>(res.error());

        res = packer.pack(caKeyPath);
        if (!res)
            return casket::PackResult<casket::Packer*>(res.error());

        return casket::PackResult<casket::Packer*>(&packer);
    }

    static casket::UnpackResult<Policy> unpack(casket::Unpacker& unpacker)
    {
        auto mapSizeResult = unpacker.unpackMapSize();
        if (!mapSizeResult)
            return casket::UnpackResult<Policy>(mapSizeResult.error());

        size_t mapSize = *mapSizeResult;
        Policy policy;

        for (size_t i = 0; i < mapSize; ++i)
        {
            auto keyResult = unpacker.unpackString();
            if (!keyResult)
                return casket::UnpackResult<Policy>(keyResult.error());

            std::string_view key = *keyResult;

            if (key == "caCertPath")
            {
                auto valueResult = unpacker.unpackString();
                if (!valueResult)
                    return casket::UnpackResult<Policy>(valueResult.error());
                policy.caCertPath = *valueResult;
            }
            else if (key == "caKeyPath")
            {
                auto valueResult = unpacker.unpackString();
                if (!valueResult)
                    return casket::UnpackResult<Policy>(valueResult.error());
                policy.caKeyPath = *valueResult;
            }
            else
            {
                auto skipResult = unpacker.unpackString();
                if (!skipResult)
                    return casket::UnpackResult<Policy>(skipResult.error());
            }
        }

        return casket::UnpackResult<Policy>(policy);
    }
};

class PolicyManager final
{
public:
    PolicyManager(const std::string& storageDir)
        : metadataPath_(storageDir + "/policies.bin")
    {
        namespace fs = std::filesystem;
        if (fs::exists(storageDir))
        {
            loadPolicies();
        }
        else
        {
            fs::create_directories(storageDir);
        }
    }

    ~PolicyManager() noexcept
    {
        savePolicies();
    }

    bool addPolicy(const std::string& name, std::shared_ptr<Policy> policy)
    {
        policies_[name] = policy;
        return savePolicies();
    }

    bool removePolicy(const std::string& name)
    {
        auto it = policies_.find(name);
        if (it != policies_.end())
        {
            policies_.erase(it);
            return savePolicies();
        }
        return false;
    }

    std::shared_ptr<Policy> getPolicy(const std::string& name)
    {
        auto it = policies_.find(name);
        return (it != policies_.end() ? it->second : nullptr);
    }

    template <typename Func>
    void processPolicies(Func&& functor)
    {
        std::for_each(policies_.begin(), policies_.end(), functor);
    }

    size_t size() const noexcept
    {
        return policies_.size();
    }

    bool empty() const noexcept
    {
        return policies_.empty();
    }

    void clear() noexcept
    {
        policies_.clear();
        savePolicies();
    }

private:
    bool savePolicies() noexcept
    {
        try
        {
            std::array<uint8_t, 65536> buffer{};
            casket::Packer packer(buffer.data(), buffer.size());

            auto res = packer.packMapStart(policies_.size());
            if (!res)
                return false;

            for (const auto& [name, policy] : policies_)
            {
                res = packer.pack(name);
                if (!res)
                    return false;

                res = policy->pack(packer);
                if (!res)
                    return false;
            }

            // Сначала пишем во временный файл
            std::string tempPath = metadataPath_ + ".tmp";
            std::ofstream file(tempPath, std::ios::binary);
            if (!file)
                return false;

            uint32_t dataSize = static_cast<uint32_t>(packer.position());
            file.write(reinterpret_cast<const char*>(&dataSize), sizeof(dataSize));
            file.write(reinterpret_cast<const char*>(packer.data()), packer.position());
            file.close();

            if (!file.good())
                return false;

            // Атомарно заменяем файл
            namespace fs = std::filesystem;
            fs::rename(tempPath, metadataPath_);

            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    bool loadPolicies() noexcept
    {
        try
        {
            std::ifstream file(metadataPath_, std::ios::binary);
            if (!file)
                return true;

            uint32_t dataSize = 0;
            file.read(reinterpret_cast<char*>(&dataSize), sizeof(dataSize));
            if (!file || dataSize == 0 || dataSize > 1024 * 1024)
                return false;

            std::vector<uint8_t> buffer(dataSize);
            file.read(reinterpret_cast<char*>(buffer.data()), dataSize);
            if (!file)
                return false;

            casket::Unpacker unpacker(buffer.data(), buffer.size());

            auto mapSizeResult = unpacker.unpackMapSize();
            if (!mapSizeResult)
                return false;

            policies_.clear();

            for (size_t i = 0; i < *mapSizeResult; ++i)
            {
                auto nameResult = unpacker.unpackString();
                if (!nameResult)
                    return false;

                auto policyResult = Policy::unpack(unpacker);
                if (!policyResult)
                    return false;

                policies_[std::string(*nameResult)] = std::make_shared<Policy>(*policyResult);
            }

            return true;
        }
        catch (...)
        {
            return false;
        }
    }

private:
    std::map<std::string, std::shared_ptr<Policy>> policies_;
    std::string metadataPath_;
};

} // namespace snet