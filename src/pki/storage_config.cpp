#include <snet/pki/storage_config.hpp>

using namespace casket::opt;

namespace snet::pki
{

StorageConfig::StorageConfig()
{
    addOption(OptionBuilder("storage_dir", Value(&storageDir)).setDefaultValue("${HOME}/.snet_pkimgr/").build());
    addOption(OptionBuilder("policy_metadata", Value(&policyMetadataFile)).setDefaultValue("policies.bin").build());
    addOption(OptionBuilder("certs_metadata", Value(&certsMetadataFile)).setDefaultValue("certificates.db").build());
    addOption(OptionBuilder("ca_cert_name", Value(&caCertName)).setDefaultValue("ca.crt").build());
    addOption(OptionBuilder("ca_key_name", Value(&caKeyName)).setDefaultValue("ca.key").build());
    addOption(OptionBuilder("cert_cache_size", Value(&certCacheSize)).setDefaultValue(1024).build());
}

std::string StorageConfig::name()
{
    return "storage";
}

std::filesystem::path StorageConfig::getPolicyPath(const std::string& name) const
{
    return std::filesystem::path(storageDir) / name;
}

std::string StorageConfig::getPolicyMetadataPath() const
{
    return (std::filesystem::path(storageDir) / policyMetadataFile).string();
}

std::string StorageConfig::getCertsMetadataPath() const
{
    return (std::filesystem::path(storageDir) / certsMetadataFile).string();
}

std::string StorageConfig::getCACertPath(const std::string& name) const
{
    return (getPolicyPath(name) / caCertName).string();
}

std::string StorageConfig::getCAKeyPath(const std::string& name) const
{
    return (getPolicyPath(name) / caKeyName).string();
}

} // namespace snet::pki