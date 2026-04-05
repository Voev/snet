#pragma once

#include <string>
#include <vector>
#include <map>

namespace snet
{

struct Profile
{
    std::string name;
    std::string caCertPath;
    std::string caKeyPath;
    int validityDays;
    std::map<std::string, std::string> extensions;
};

struct CertificateInfo
{
    std::string serialNumber;
    std::string subject;
    std::string notBefore;
    std::string notAfter;
    std::string originalPath;
    std::string renewedPath;
};

class CertificateManager
{
public:
    explicit CertificateManager(const std::string& storageDir);

    bool initDatabase();
    bool databaseExists() const;

    std::vector<Profile> getAvailableProfiles() const;
    void addProfile(const Profile& profile);

    bool renewCertificate(const std::string& certPath, const std::string& profileName, std::string& outputPath);

    std::vector<CertificateInfo> listRenewedCertificates() const;

private:
    std::string storageDir_;
    std::string dbPath_;
    std::map<std::string, Profile> profiles_;

    void loadProfiles();
    void saveProfiles();
    std::string generateSerialNumber() const;
    bool loadCertificate(const std::string& path, std::string& pemData) const;
    bool saveCertificate(const std::string& path, const std::string& pemData) const;
    bool signCertificate(const std::string& certPem, const Profile& profile, std::string& signedPem) const;
    std::string generateOutputPath(const std::string& originalPath) const;
};

} // namespace snet