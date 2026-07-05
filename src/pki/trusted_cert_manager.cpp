#include <snet/pki/trusted_cert_manager.hpp>

#include <snet/utils/time.hpp>

namespace snet::pki
{

Row TrustedCertificateRecord::toRow() const
{
    Row row(8);
    row[0] = makeFieldValue(fingerprint.toString());
    row[2] = makeFieldValue(name);
    row[1] = makeFieldValue(serialNumber);
    row[3] = makeFieldValue(subjectDN);
    row[4] = makeFieldValue(issuerDN);
    row[5] = makeFieldValue(ToIso8601(notBefore));
    row[6] = makeFieldValue(ToIso8601(notAfter));
    row[7] = makeFieldValue(certPath);
    return row;
}

TrustedCertificateRecord TrustedCertificateRecord::fromRow(const Row& row)
{
    TrustedCertificateRecord cert;
    if (row.size() >= 8)
    {
        cert.fingerprint = CertFingerprint::fromString(getFieldValue<std::string>(row[0]));
        cert.name = getFieldValue<std::string>(row[1]);
        cert.serialNumber = getFieldValue<std::string>(row[2]);
        cert.subjectDN = getFieldValue<std::string>(row[3]);
        cert.issuerDN = getFieldValue<std::string>(row[4]);
        cert.notBefore = FromIso8601(getFieldValue<std::string>(row[5])).value_or(SystemTimePoint{});
        cert.notAfter = FromIso8601(getFieldValue<std::string>(row[6])).value_or(SystemTimePoint{});
        cert.certPath = getFieldValue<std::string>(row[7]);
    }
    return cert;
}

static inline std::vector<std::type_index> getFieldTypes()
{
    return {
        typeid(std::string), // fingerprint
        typeid(std::string), // name
        typeid(std::string), // serialNumber
        typeid(std::string), // subjectDN
        typeid(std::string), // issuerDN
        typeid(std::string), // notBefore
        typeid(std::string), // notAfter
        typeid(std::string)  // certPath
    };
}

static inline TXTDatabase CreateDatabase(const StorageConfig& config)
{
    auto trustedStorageDir = config.getTrustedStorageDir();

    if (!std::filesystem::exists(trustedStorageDir))
    {
        std::filesystem::create_directories(trustedStorageDir);
    }

    auto indexFile = trustedStorageDir / "index.txt";

    if (std::filesystem::exists(indexFile))
    {
        return TXTDatabase::readFromFile(indexFile, getFieldTypes());
    }
    else
    {
        return TXTDatabase(getFieldTypes());
    }
}

TrustedCertManager::TrustedCertManager(const StorageConfig& config)
    : config_(config)
    , db_(CreateDatabase(config))
    , certCache_(config.certCacheSize)
{
    db_.createIndex(0); // by fingerprint
    db_.createIndex(1); // by policy name

    rebuildCache();
}

void TrustedCertManager::insertCertificate(const std::string& name, const CertFingerprint& fingerprint, X509Cert* cert)
{
    casket::ThrowIfFalse(cert, "invalid certificate");

    auto path = config_.getTrustedStorageDir();
    path /= fingerprint.toString() + ".0";
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
            casket::ThrowIfFalse(db_.insert(record.toRow()), "Failed to insert certificate: " + db_.getLastError());
        },
        [&]()
        {
            auto fieldValue = makeFieldValue(fingerprint.toString());
            db_.removeByIndex(0, fieldValue);
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
            db_.writeToFile(config_.getTrustedCertsIndex());
        });

    chain.execute();
}

crypto::X509CertPtr TrustedCertManager::findByFingerprint(const CertFingerprint& fp, const SteadyTimePoint& tp)
{
    if (auto val = certCache_.get(fp, tp))
    {
        return crypto::Cert::shallowCopy(*val);
    }
    return nullptr;
}

std::vector<TrustedCertificateRecord> TrustedCertManager::findByName(const std::string& name) const
{
    std::vector<TrustedCertificateRecord> result;

    auto fieldValue = makeFieldValue(name);
    const Row* row = db_.findByIndex(1, fieldValue);
    if (row)
    {
        result.push_back(TrustedCertificateRecord::fromRow(*row));
    }
    return result;
}

size_t TrustedCertManager::size() const noexcept
{
    return certCache_.size();
}

const L1CertCache& TrustedCertManager::getAllCerts() const noexcept
{
    return certCache_;
}

void TrustedCertManager::rebuildCache()
{
    certCache_.clear();

    for (size_t i = 0; i < db_.size(); i++)
    {
        const auto& row = db_.getRow(i);
        auto record = TrustedCertificateRecord::fromRow(row);

        auto cert = crypto::Cert::fromStorage(record.certPath);
        certCache_.put(record.fingerprint, std::move(cert), SystemToSteady(record.notAfter));
    }
}

} // namespace snet::pki