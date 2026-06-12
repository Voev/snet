#include <fstream>
#include <sys/stat.h>
#include "config_manager.hpp"

using namespace casket::opt;

namespace snet
{

static inline bool fileExists(const std::string& path)
{
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

ConfigManager::ConfigManager()
{
    options_.add<GenericSection>();
}

ConfigManager::~ConfigManager()
{
}

void ConfigManager::initialize(const std::string& configPath)
{
    if (!fileExists(configPath))
    {
        createDefaultConfig(configPath);
    }

    read(configPath);
}

void ConfigManager::read(const std::string& configFile)
{

    ConfigOptionsReader reader;
    std::ifstream ifs(configFile);

    reader.read(ifs, options_);
}

const GenericSection* ConfigManager::generic() const
{
    return options_.get<GenericSection>();
}

void ConfigManager::createDefaultConfig(const std::string& configPath)
{
    std::string dirPath = configPath.substr(0, configPath.find_last_of('/'));
    if (!dirPath.empty())
    {
        std::string command = "mkdir -p " + dirPath;
        system(command.c_str());
    }

    std::ofstream configFile(configPath);
    if (!configFile.is_open())
    {
        throw std::runtime_error("Cannot create config file: " + configPath);
    }

    configFile << "# SNET PKI Manager Configuration File\n";
    configFile << "# Generated automatically on first run: " << __DATE__ << " " << __TIME__ << "\n\n";

    auto section = options_.find("generic");
    section->validate();

    const auto* generic = options_.get<GenericSection>();
    configFile << "generic {\n";
    configFile << "\tpolicy_dir = " << generic->getOption("policy_dir").get<std::string>() + "\n";
    configFile << "\tsocket_path = " << generic->getOption("socket_path").get<std::string>() + "\n";
    configFile << "}\n";
    configFile.close();

    chmod(configPath.c_str(), 0644);
}

} // namespace snet