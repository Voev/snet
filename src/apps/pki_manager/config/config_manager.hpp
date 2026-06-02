#pragma once
#include <casket/opt/opt.hpp>
#include <casket/opt/config_options_reader.hpp>

namespace snet
{

class GenericSection : public casket::opt::Section
{
public:
    GenericSection()
    {
        addOption(casket::opt::OptionBuilder("policy_dir", casket::opt::Value(&policyDirectory))
                      .setDefaultValue("/home/voev/.pki_manager/")
                      .build());
        addOption(casket::opt::OptionBuilder("socket_path", casket::opt::Value(&policyDirectory))
                      .setDefaultValue("/tmp/pki_manager.sock")
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

private:
    void createDefaultConfig(const std::string& configPath);

private:
    casket::opt::ConfigOptions options_;
};

} // namespace snet