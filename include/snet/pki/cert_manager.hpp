#pragma once
#include <cstdint>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <string>
#include <optional>

#include <snet/pki/cert_fingerprint.hpp>
#include <snet/pki/cert_status.hpp>
#include <snet/pki/cert_cache.hpp>

#include <snet/pki/storage_config.hpp>

#include <snet/utils/file_db.hpp>
#include <snet/utils/action_chain.hpp>
#include <snet/crypto/cert.hpp>

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
    CertStatus status;
    std::string certPath;

    CertificateRecord()
        : status(CertStatus::UNKNOWN)
    {
    }

    Row toRow() const
    {
        Row row(9);
        row[0] = makeFieldValue(fingerprint.toString());
        row[1] = makeFieldValue(serialNumber);
        row[2] = makeFieldValue(policyName);
        row[3] = makeFieldValue(subjectDN);
        row[4] = makeFieldValue(issuerDN);
        row[5] = makeFieldValue(formatTimePoint(notBefore));
        row[6] = makeFieldValue(formatTimePoint(notAfter));
        row[7] = makeFieldValue(CertStatusToString(status));
        row[8] = makeFieldValue(certPath);
        return row;
    }

    static CertificateRecord fromRow(const Row& row)
    {
        CertificateRecord cert;
        if (row.size() >= 9)
        {
            cert.fingerprint = CertFingerprint::fromString(getFieldValue<std::string>(row[0]));
            cert.policyName = getFieldValue<std::string>(row[1]);
            cert.serialNumber = getFieldValue<std::string>(row[2]);
            cert.subjectDN = getFieldValue<std::string>(row[3]);
            cert.issuerDN = getFieldValue<std::string>(row[4]);
            cert.notBefore = parseTimePoint(getFieldValue<std::string>(row[5]));
            cert.notAfter = parseTimePoint(getFieldValue<std::string>(row[6]));
            cert.status = StringToCertStatus(getFieldValue<std::string>(row[7]));
            cert.certPath = getFieldValue<std::string>(row[8]);
        }
        return cert;
    }

private:
    static std::string formatTimePoint(const std::chrono::system_clock::time_point& tp)
    {
        auto time_t = std::chrono::system_clock::to_time_t(tp);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    static std::chrono::system_clock::time_point parseTimePoint(const std::string& dateStr)
    {
        std::tm tm = {};
        std::stringstream ss(dateStr);
        ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
        if (ss.fail())
        {
            ss.clear();
            ss.str(dateStr);
            ss >> std::get_time(&tm, "%Y-%m-%d");
        }
        return std::chrono::system_clock::from_time_t(std::mktime(&tm));
    }
};

class CertManager final
{
private:
    const StorageConfig& config_;
    std::unique_ptr<TXTDatabase> db_;
    L1CertCache certCache_;

    void rebuildCache()
    {
        certCache_.clear();

        for (size_t i = 0; i < db_->size(); i++)
        {
            const auto& row = db_->getRow(i);
            auto record = CertificateRecord::fromRow(row);

            auto cert = crypto::Cert::fromStorage(record.certPath);
            certCache_.put(record.fingerprint, std::move(cert), SystemToSteady(record.notAfter));
        }
    }

    static std::vector<std::type_index> getFieldTypes()
    {

        return {
            typeid(std::string), // fingerprint
            typeid(std::string), // policyName
            typeid(std::string), // serialNumber
            typeid(std::string), // subjectDN
            typeid(std::string), // issuerDN
            typeid(std::string), // notBefore
            typeid(std::string), // notAfter
            typeid(std::string), // status
            typeid(std::string)  // certPath
        };
    }

public:
    explicit CertManager(const StorageConfig& config)
        : config_(config)
        , certCache_(config.certCacheSize)
    {
        auto metadataPath = config_.getCertsMetadataPath();

        if (std::filesystem::exists(metadataPath))
        {
            db_ = std::make_unique<TXTDatabase>(TXTDatabase::readFromFile(metadataPath, getFieldTypes()));
            rebuildCache();
        }
        else
        {
            db_ = std::make_unique<TXTDatabase>(getFieldTypes());
        }

        db_->createIndex(0); // by fingerprint
        db_->createIndex(1); // by policy name
    }

    ~CertManager() noexcept = default;

    void insertCertificate(const std::string& policyName, const CertFingerprint& fingerprint, X509Cert* cert)
    {
        casket::ThrowIfFalse(cert, "invalid certificate");

        auto path = config_.getPolicyPath(policyName);
        path /= fingerprint.toString() + ".crt";
        std::string certPath = path.string();

        CertificateRecord record;
        record.fingerprint = fingerprint;
        record.policyName = policyName;
        record.serialNumber = crypto::Cert::serialNumberString(cert);
        record.subjectDN = crypto::Cert::subjectNameString(cert);
        record.issuerDN = crypto::Cert::issuerNameString(cert);
        record.notBefore = crypto::Cert::notBeforeTimePoint(cert);
        record.notAfter = crypto::Cert::notAfterTimePoint(cert);
        record.status = CertStatus::VALID;
        record.certPath = certPath;

        ActionChain chain;

        chain.addAction(
            [&cert, &certPath]()
            {
                auto bio = crypto::BioTraits::openFile(certPath, "wb");
                crypto::Cert::toBio(cert, bio, Encoding::PEM);
            },
            [&certPath]()
            {
                std::filesystem::remove(certPath);
            });

        chain.addAction(
            [&]()
            {
                casket::ThrowIfFalse(db_->insert(record.toRow()),
                                     "Failed to insert certificate: " + db_->getLastError());
            },
            [&]()
            {
                auto fieldValue = makeFieldValue(fingerprint.toString());
                db_->removeByIndex(0, fieldValue);
            });

        chain.addAction(
            [&]()
            {
                casket::ThrowIfFalse(db_->insert(record.toRow()),
                                     "Failed to insert certificate: " + db_->getLastError());
            },
            [&]()
            {
                auto fieldValue = makeFieldValue(fingerprint.toString());
                db_->removeByIndex(0, fieldValue);
            });

        chain.addAction(
            [&]()
            {
                certCache_.put(fingerprint, crypto::Cert::shallowCopy(cert), SystemToSteady(record.notAfter));
            },
            [&]()
            {
                certCache_.erase(fingerprint);
            });

        chain.addAction(
            [&]()
            {
                db_->writeToFile(config_.getCertsMetadataPath());
            },
            []()
            {
            });

        chain.execute();
    }

    crypto::X509CertPtr findByFingerprint(const CertFingerprint& fp, const SteadyTimePoint& tp)
    {
        if (auto val = certCache_.get(fp, tp))
        {
            return crypto::Cert::shallowCopy(*val);
        }
        return nullptr;
    }

    std::vector<CertificateRecord> findByPolicy(const std::string& policyName) const
    {
        std::vector<CertificateRecord> result;

        auto fieldValue = makeFieldValue(policyName);
        const Row* row = db_->findByIndex(1, fieldValue);
        if (row)
        {
            result.push_back(CertificateRecord::fromRow(*row));
        }
        return result;
    }

    size_t size() const noexcept
    {
        return certCache_.size();
    }

    const L1CertCache& getAllCerts() const noexcept
    {
        return certCache_;
    }
};

} // namespace snet::pki