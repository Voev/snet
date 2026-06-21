#pragma once
#include <cstdint>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <string>

#include <snet/pki/cert_fingerprint.hpp>
#include <snet/pki/cert_status.hpp>
#include <snet/pki/cert_cache.hpp>
#include <snet/pki/storage_config.hpp>

#include <snet/utils/file_db.hpp>
#include <snet/crypto/cert.hpp>

#include <casket/utils/action_chain.hpp>
#include <casket/utils/noncopyable.hpp>

namespace snet::pki
{

struct CertificateRecord
{
    CertFingerprint fingerprint;
    std::string policyName;
    std::string serialNumber;
    std::string subjectDN;
    std::string issuerDN;
    SystemTimePoint notBefore;
    SystemTimePoint notAfter;
    CertStatus status{CertStatus::UNKNOWN};
    std::string certPath;

    Row toRow() const;

    static CertificateRecord fromRow(const Row& row);
};

class CertManager final : casket::NonCopyable
{
public:
    explicit CertManager(const StorageConfig& config);

    ~CertManager() noexcept = default;

    CertManager(CertManager&&) noexcept = default;
    
    CertManager& operator=(CertManager&&) noexcept = default;

    void insertCertificate(const std::string& policyName, const CertFingerprint& fingerprint, X509Cert* cert);

    crypto::X509CertPtr findByFingerprint(const CertFingerprint& fp, const SteadyTimePoint& tp);

    std::vector<CertificateRecord> findByPolicy(const std::string& policyName) const;

    size_t size() const noexcept;

    const L1CertCache& getAllCerts() const noexcept;

private:
    void rebuildCache();

private:
    const StorageConfig& config_;
    TXTDatabase db_;
    L1CertCache certCache_;
};

} // namespace snet::pki