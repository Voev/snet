#pragma once
#include <cstdint>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <string>
#include <memory>

#include <snet/pki/cert_fingerprint.hpp>
#include <snet/pki/cert_status.hpp>
#include <snet/pki/cert_cache.hpp>
#include <snet/pki/storage_config.hpp>

#include <snet/crypto/cert.hpp>

#include <casket/db/i_database.hpp>

#include <casket/utils/action_chain.hpp>
#include <casket/utils/noncopyable.hpp>

namespace snet::pki
{

struct TrustedCertificateRecord
{
    CertFingerprint fingerprint;
    std::string name;
    std::string serialNumber;
    std::string subjectDN;
    std::string issuerDN;
    SystemTimePoint notBefore;
    SystemTimePoint notAfter;
    std::string certPath;

    std::shared_ptr<casket::db::IRow> toRow() const;

    static TrustedCertificateRecord fromRow(const casket::db::IRow& row);
};

class TrustedCertManager final : casket::NonCopyable
{
public:
    explicit TrustedCertManager(const StorageConfig& config);

    ~TrustedCertManager() noexcept = default;

    TrustedCertManager(TrustedCertManager&&) noexcept = default;
    
    TrustedCertManager& operator=(TrustedCertManager&&) noexcept = default;

    void insertCertificate(const std::string& name, const CertFingerprint& fingerprint, X509Cert* cert);

    std::vector<TrustedCertificateRecord> findByName(const std::string& name) const;

    size_t size() const noexcept;

private:
    const StorageConfig& config_;
    std::unique_ptr<casket::db::IDatabase> db_;
};

} // namespace snet::pkis