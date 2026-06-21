#pragma once
#include <casket/opt/opt.hpp>

namespace snet::pki
{

class StorageConfig final : public casket::opt::Section
{
public:
    StorageConfig();

    ~StorageConfig() noexcept = default;

    static std::string name();

    std::filesystem::path getPolicyPath(const std::string& name) const;

    std::string getPolicyMetadataPath() const;

    std::string getCertsMetadataPath() const;

    std::string getCACertPath(const std::string& name) const;

    std::string getCAKeyPath(const std::string& name) const;

public:
    std::string storageDir;
    std::string policyMetadataFile;
    std::string certsMetadataFile;
    std::string caCertName;
    std::string caKeyName;
    std::size_t certCacheSize{1024};
};

} // namespace snet::pki