#include <snet/pki/cert_manager.hpp>

#include <snet/utils/time.hpp>

#include <casket/db/txt/txt_database.hpp>
#include <casket/db/field_extractor.hpp>

using namespace casket;

namespace fs = std::filesystem;

static inline std::vector<std::type_index> GetFieldTypes()
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

namespace snet::pki
{

std::shared_ptr<db::IRow> CertificateRecord::toRow() const
{
    auto row = std::make_shared<db::TxtRow>(::GetFieldTypes());
    row->setField(0, db::makeFieldValue(fingerprint.toString()));
    row->setField(1, db::makeFieldValue(policyName));
    row->setField(2, db::makeFieldValue(serialNumber));
    row->setField(3, db::makeFieldValue(subjectDN));
    row->setField(4, db::makeFieldValue(issuerDN));
    row->setField(5, db::makeFieldValue(ToIso8601(notBefore)));
    row->setField(6, db::makeFieldValue(ToIso8601(notAfter)));
    row->setField(7, db::makeFieldValue(CertStatusToString(status)));
    row->setField(8, db::makeFieldValue(certPath));
    return row;
}

CertificateRecord CertificateRecord::fromRow(const db::IRow& row)
{
    CertificateRecord cert;
    if (row.size() >= 9)
    {
        cert.fingerprint = CertFingerprint::fromString(db::extractField<std::string>(row, 0));
        cert.policyName = db::extractField<std::string>(row, 1);
        cert.serialNumber = db::extractField<std::string>(row, 2);
        cert.subjectDN = db::extractField<std::string>(row, 3);
        cert.issuerDN = db::extractField<std::string>(row, 4);
        cert.notBefore = FromIso8601(db::extractField<std::string>(row, 5)).value_or(SystemTimePoint{});
        cert.notAfter = FromIso8601(db::extractField<std::string>(row, 6)).value_or(SystemTimePoint{});
        cert.status = StringToCertStatus(db::extractField<std::string>(row, 7));
        cert.certPath = db::extractField<std::string>(row, 8);
    }
    return cert;
}

static inline std::unique_ptr<db::IDatabase> CreateDatabase(const StorageConfig& config)
{
    auto metadataPath = config.getCertsMetadataPath();

    auto db = std::make_unique<db::TxtDatabase>(::GetFieldTypes());

    if (std::filesystem::exists(metadataPath))
    {
        db->readFromFile(metadataPath);
    }

    return db;
}

CertManager::CertManager(const StorageConfig& config)
    : config_(config)
    , db_(CreateDatabase(config))
    , certCache_(config.certCacheSize)
{
    db_->createIndex(0); // by fingerprint
    db_->createIndex(1); // by policy name

    rebuildCache();
}

void CertManager::insertCertificate(const std::string& policyName, const CertFingerprint& fingerprint, X509Cert* cert)
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

    casket::ActionChain chain;

    chain.addAction(
        [&]()
        {
            auto bio = crypto::BioTraits::openFile(certPath, "wb");
            crypto::Cert::toBio(cert, bio, Encoding::PEM);
        },
        [&]()
        {
            std::error_code ec;
            std::filesystem::remove(certPath, ec);
        });

    chain.addAction(
        [&]()
        {
            if (!db_->insert(record.toRow()))
            {
                throw casket::RuntimeError(
                    "{} row: {}, field: {}", db_->getLastError(), db_->getErrorRow(), db_->getErrorField());
            }
        },
        [&]()
        {
            auto fieldValue = db::makeFieldValue(fingerprint.toString());
            const auto* foundRow = db_->findByIndex(0, fieldValue);
            if (foundRow)
            {
                for (size_t i = 0; i < db_->size(); ++i)
                {
                    if (&db_->getRow(i) == foundRow)
                    {
                        db_->remove(i);
                        break;
                    }
                }
            }
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
        });

    chain.execute();
}

crypto::X509CertPtr CertManager::findByFingerprint(const CertFingerprint& fp, const SteadyTimePoint& tp)
{
    if (auto val = certCache_.get(fp, tp))
    {
        return crypto::Cert::shallowCopy(*val);
    }
    return nullptr;
}

std::vector<CertificateRecord> CertManager::findByPolicy(const std::string& policyName) const
{
    std::vector<CertificateRecord> result;

    auto fieldValue = db::makeFieldValue(policyName);
    const db::IRow* row = db_->findByIndex(1, fieldValue);
    if (row)
    {
        result.push_back(CertificateRecord::fromRow(*row));
    }
    return result;
}

size_t CertManager::size() const noexcept
{
    return certCache_.size();
}

const L1CertCache& CertManager::getAllCerts() const noexcept
{
    return certCache_;
}

void CertManager::rebuildCache()
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

} // namespace snet::pki