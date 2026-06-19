#pragma once
#include <casket/opt/opt.hpp>
#include <casket/opt/config_options_reader.hpp>
#include <snet/pki/storage_config.hpp>

namespace snet
{

class GenericSection : public casket::opt::Section
{
public:
    GenericSection()
    {
        addOption(casket::opt::OptionBuilder("policy_dir", casket::opt::Value(&policyDirectory))
                      .setDefaultValue("${HOME}/.snet_pkimgr/")
                      .build());
        addOption(casket::opt::OptionBuilder("socket_path", casket::opt::Value(&socketName))
                      .setDefaultValue("${HOME}/snet_pkimgr.sock")
                      .build());
    }

    static std::string name()
    {
        return "generic";
    }

    std::string policyDirectory;
    std::string socketName;
};

class ConfigManager
{
public:
    ConfigManager();

    ~ConfigManager();

    void initialize(const std::string& configPath);

    void read(const std::string& configPath);

    const GenericSection* generic() const;

    const pki::StorageConfig* storage() const;

private:
    void createDefaultConfig(const std::string& configPath);

private:
    casket::opt::ConfigOptions options_;
};

} // namespace snet