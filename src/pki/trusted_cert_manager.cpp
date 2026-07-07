#include <snet/pki/trusted_cert_manager.hpp>
#include <snet/pki/cert_name_hash.hpp>

#include <snet/utils/time.hpp>

#include <casket/db/field_extractor.hpp>
#include <casket/db/txt/txt_database.hpp>

using namespace casket;

static inline std::vector<std::type_index> GetFieldTypes()
{
    return {
        typeid(std::string),     // fingerprint
        typeid(std::string),     // name
        typeid(std::string),     // serialNumber
        typeid(std::string),     // subjectDN
        typeid(std::string),     // issuerDN
        typeid(snet::SystemTimePoint), // notBefore
        typeid(snet::SystemTimePoint), // notAfter
        typeid(std::string)      // certPath
    };
}

namespace snet::pki
{

std::shared_ptr<casket::db::IRow> TrustedCertificateRecord::toRow() const
{
    auto row = std::make_shared<casket::db::TxtRow>(::GetFieldTypes());
    row->setField(0, db::makeFieldValue(fingerprint.toString()));
    row->setField(1, db::makeFieldValue(name));
    row->setField(2, db::makeFieldValue(serialNumber));
    row->setField(3, db::makeFieldValue(subjectDN));
    row->setField(4, db::makeFieldValue(issuerDN));
    row->setField(5, db::makeFieldValue(notBefore));
    row->setField(6, db::makeFieldValue(notAfter));
    row->setField(7, db::makeFieldValue(certPath));
    return row;
}

TrustedCertificateRecord TrustedCertificateRecord::fromRow(const db::IRow& row)
{
    TrustedCertificateRecord cert;
    if (row.size() >= 8)
    {
        cert.fingerprint = CertFingerprint::fromString(db::extractField<std::string>(row, 0));
        cert.name = db::extractField<std::string>(row, 1);
        cert.serialNumber = db::extractField<std::string>(row, 2);
        cert.subjectDN = db::extractField<std::string>(row, 3);
        cert.issuerDN = db::extractField<std::string>(row, 4);
        cert.notBefore = db::extractField<SystemTimePoint>(row, 5);
        cert.notAfter = db::extractField<SystemTimePoint>(row, 6);
        cert.certPath = db::extractField<std::string>(row, 7);
    }
    return cert;
}

static inline std::unique_ptr<db::IDatabase> CreateDatabase(const StorageConfig& config)
{
    auto trustedStorageDir = config.getTrustedStorageDir();

    if (!std::filesystem::exists(trustedStorageDir))
    {
        std::filesystem::create_directories(trustedStorageDir);
    }

    auto indexFile = trustedStorageDir / "index.txt";

    auto db = std::make_unique<db::TxtDatabase>(::GetFieldTypes());

    if (std::filesystem::exists(indexFile))
    {
        db->readFromFile(indexFile.string());
    }

    return db;
}

TrustedCertManager::TrustedCertManager(const StorageConfig& config)
    : config_(config)
    , db_(CreateDatabase(config))
{
    db_->createIndex(0); // by fingerprint
    db_->createIndex(1); // by name
}

void TrustedCertManager::insertCertificate(const std::string& name, const CertFingerprint& fingerprint, X509Cert* cert)
{
    casket::ThrowIfFalse(cert, "invalid certificate");

    auto certHash = CertNameHashGenerator::fromCert(cert);

    auto path = config_.getTrustedStorageDir();
    path /= certHash.toString() + ".0";
    std::string certPath = path.string();

    TrustedCertificateRecord record;
    record.fingerprint = fingerprint;
    record.name = name;
    record.serialNumber = crypto::Cert::serialNumberString(cert);
    record.subjectDN = crypto::Cert::subjectNameString(cert);
    record.issuerDN = crypto::Cert::issuerNameString(cert);
    record.notBefore = crypto::Cert::notBeforeTimePoint(cert);
    record.notAfter = crypto::Cert::notAfterTimePoint(cert);
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
            auto fpValue = db::makeFieldValue(fingerprint.toString());
            const auto* row = db_->findByIndex(0, fpValue);
            if (row)
            {
                for (size_t i = 0; i < db_->size(); ++i)
                {
                    const auto& currentRow = db_->getRow(i);
                    if (&currentRow == row)
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
            db_->writeToFile(config_.getTrustedCertsIndex());
        });

    chain.execute();
}

std::vector<TrustedCertificateRecord> TrustedCertManager::findByName(const std::string& name) const
{
    std::vector<TrustedCertificateRecord> result;

    auto stmt = db_->createStatement();
    stmt->whereEquals(1, db::makeFieldValue(name));
    result.reserve(stmt->spin());

    while (stmt->step())
    {
        const db::IRow* row = stmt->current();
        if (row)
        {
            result.push_back(TrustedCertificateRecord::fromRow(*row));
        }
    }

    return result;
}

size_t TrustedCertManager::size() const noexcept
{
    return db_->size();
}

} // namespace snet::pki