
#include <fstream>
#include <iostream>
#include <sstream>
#include <filesystem>
#include <chrono>
#include <random>
#include <iomanip>
#include <snet/cert_cache/cert_manager.hpp>

namespace fs = std::filesystem;

namespace snet
{

CertificateManager::CertificateManager(const std::string& storageDir)
    : storageDir_(storageDir)
    , dbPath_(storageDir + "/metadata.json")
{
    fs::create_directories(storageDir);
    loadProfiles();
}

bool CertificateManager::initDatabase()
{
    if (databaseExists())
    {
        return false; // Already exists
    }

    fs::create_directories(storageDir_);

    std::ofstream dbFile(dbPath_);
    if (!dbFile)
    {
        return false;
    }

    // Initialize empty profiles
    profiles_.clear();
    saveProfiles();

    return true;
}

bool CertificateManager::databaseExists() const
{
    return fs::exists(dbPath_);
}

std::vector<Profile> CertificateManager::getAvailableProfiles() const
{
    std::vector<Profile> profiles;
    for (const auto& [name, profile] : profiles_)
    {
        profiles.push_back(profile);
    }
    return profiles;
}

void CertificateManager::addProfile(const Profile& profile)
{
    profiles_[profile.name] = profile;
    saveProfiles();
}

bool CertificateManager::renewCertificate(const std::string& certPath, const std::string& profileName,
                                          std::string& outputPath)
{
    // Check if profile exists
    auto it = profiles_.find(profileName);
    if (it == profiles_.end())
    {
        return false;
    }

    const Profile& profile = it->second;

    // Load original certificate
    std::string certPem;
    if (!loadCertificate(certPath, certPem))
    {
        return false;
    }

    // Sign with profile
    std::string signedPem;
    if (!signCertificate(certPem, profile, signedPem))
    {
        return false;
    }

    // Generate output path
    outputPath = generateOutputPath(certPath);
    if (!saveCertificate(outputPath, signedPem))
    {
        return false;
    }

    return true;
}

std::vector<CertificateInfo> CertificateManager::listRenewedCertificates() const
{
    std::vector<CertificateInfo> certificates;

    if (!fs::exists(storageDir_))
    {
        return certificates;
    }

    for (const auto& entry : fs::directory_iterator(storageDir_))
    {
        if (entry.path().extension() == ".crt" || entry.path().extension() == ".pem")
        {
            CertificateInfo info;
            info.originalPath = "unknown"; // Would need to parse from metadata
            info.renewedPath = entry.path().string();
            // Parse certificate for more info
            certificates.push_back(info);
        }
    }

    return certificates;
}

void CertificateManager::loadProfiles()
{
    if (!fs::exists(dbPath_))
    {
        return;
    }

    std::ifstream dbFile(dbPath_);
    if (!dbFile)
    {
        return;
    }

    std::string content((std::istreambuf_iterator<char>(dbFile)), std::istreambuf_iterator<char>());

    // Simple JSON parsing (in production, use a library like nlohmann/json)
    profiles_.clear();

    // Example profile structure - you'd parse JSON here
    // For simplicity, adding a default profile
    Profile defaultProfile;
    defaultProfile.name = "default";
    defaultProfile.caCertPath = storageDir_ + "/ca.crt";
    defaultProfile.caKeyPath = storageDir_ + "/ca.key";
    defaultProfile.validityDays = 365;
    profiles_["default"] = defaultProfile;
}

void CertificateManager::saveProfiles()
{
    std::ofstream dbFile(dbPath_);
    if (!dbFile)
    {
        return;
    }

    // Simple JSON serialization (in production, use a proper JSON library)
    dbFile << "{\n  \"profiles\": [\n";
    bool first = true;
    for (const auto& [name, profile] : profiles_)
    {
        if (!first)
            dbFile << ",\n";
        dbFile << "    {\n";
        dbFile << "      \"name\": \"" << profile.name << "\",\n";
        dbFile << "      \"caCertPath\": \"" << profile.caCertPath << "\",\n";
        dbFile << "      \"caKeyPath\": \"" << profile.caKeyPath << "\",\n";
        dbFile << "      \"validityDays\": " << profile.validityDays << "\n";
        dbFile << "    }";
        first = false;
    }
    dbFile << "\n  ]\n}\n";
}

std::string CertificateManager::generateSerialNumber() const
{
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 65535);

    std::ostringstream oss;
    oss << std::hex << timestamp << std::setw(4) << std::setfill('0') << dis(gen);
    return oss.str();
}

bool CertificateManager::loadCertificate(const std::string& path, std::string& pemData) const
{
    std::ifstream certFile(path);
    if (!certFile)
    {
        return false;
    }

    pemData = std::string((std::istreambuf_iterator<char>(certFile)), std::istreambuf_iterator<char>());
    return !pemData.empty();
}

bool CertificateManager::saveCertificate(const std::string& path, const std::string& pemData) const
{
    std::ofstream outFile(path);
    if (!outFile)
    {
        return false;
    }

    outFile << pemData;
    return true;
}

bool CertificateManager::signCertificate(const std::string& certPem, const Profile& profile,
                                         std::string& signedPem) const
{
    // This is a placeholder for actual certificate signing logic
    // In production, you would use OpenSSL or similar library

    // For demonstration, we just append the profile name as a marker
    signedPem = certPem;
    signedPem += "\n# Signed with profile: " + profile.name + "\n";
    signedPem += "# Validity: " + std::to_string(profile.validityDays) + " days\n";

    return true;
}

std::string CertificateManager::generateOutputPath(const std::string& originalPath) const
{
    fs::path original(originalPath);
    std::string stem = original.stem().string();
    std::string extension = original.extension().string();

    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

    std::ostringstream oss;
    oss << storageDir_ << "/" << stem << "_renewed_" << timestamp << extension;
    return oss.str();
}

} // namespace snet