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

    Row toRow() const;

    static TrustedCertificateRecord fromRow(const Row& row);
};

class TrustedCertManager final : casket::NonCopyable
{
public:
    explicit TrustedCertManager(const StorageConfig& config);

    ~TrustedCertManager() noexcept = default;

    TrustedCertManager(TrustedCertManager&&) noexcept = default;
    
    TrustedCertManager& operator=(TrustedCertManager&&) noexcept = default;

    void insertCertificate(const std::string& name, const CertFingerprint& fingerprint, X509Cert* cert);

    crypto::X509CertPtr findByFingerprint(const CertFingerprint& fp, const SteadyTimePoint& tp);

    std::vector<TrustedCertificateRecord> findByName(const std::string& policyName) const;

    size_t size() const noexcept;

    const L1CertCache& getAllCerts() const noexcept;

private:
    void rebuildCache();

private:
    const StorageConfig& config_;
    TXTDatabase db_;
    L1CertCache certCache_;
};

} // namespace snet::pkis