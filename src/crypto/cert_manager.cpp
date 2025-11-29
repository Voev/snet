#include <snet/crypto/cert_manager.hpp>
#include <snet/crypto/exception.hpp>

#include <casket/utils/exception.hpp>

namespace fs = std::filesystem;

namespace snet::crypto
{

CertManager::CertManager()
    : store_(X509_STORE_new())
{
    casket::ThrowIfTrue(store_ == nullptr, "memory allocation error");
}

CertManager::~CertManager() noexcept
{
}

CertManager& CertManager::useDefaultPaths()
{
    crypto::ThrowIfFalse(0 < X509_STORE_set_default_paths(store_));
    return *this;
}

CertManager& CertManager::addCA(X509Cert* cert)
{
    casket::ThrowIfTrue(cert == nullptr, "invalid argument");
    crypto::ThrowIfFalse(0 < X509_STORE_add_cert(store_, cert));
    return *this;
}

CertManager& CertManager::addCRL(X509Crl* crl)
{
    casket::ThrowIfTrue(crl == nullptr, "invalid argument");
    crypto::ThrowIfFalse(0 < X509_STORE_add_crl(store_, crl));
    return *this;
}

CertManager& CertManager::loadFile(const std::filesystem::path& path)
{
    fs::path caPath = fs::is_symlink(path) ? fs::read_symlink(path) : path;
    casket::ThrowIfFalse(fs::is_regular_file(caPath), "'" + path.string() + "' is not a file!");
    crypto::ThrowIfFalse(0 < X509_STORE_load_locations(store_, path.c_str(), nullptr));
    return *this;
}

CertManager& CertManager::loadDirectory(const std::filesystem::path& path)
{
    fs::path caDir = fs::is_symlink(path) ? fs::read_symlink(path) : path;
    casket::ThrowIfFalse(fs::is_directory(caDir), "'" + path.string() + "' is not a directory!");
    crypto::ThrowIfFalse(0 < X509_STORE_load_locations(store_, nullptr, path.c_str()));
    return *this;
}

CertManager& CertManager::loadStore(std::string_view uri)
{
    casket::ThrowIfTrue(uri.empty(), "URI is empty");
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    crypto::ThrowIfFalse(0 < X509_STORE_load_store(store_, uri.data()));
#else
    throw casket::RuntimeError("Not implemented");
#endif
    return *this;
}

X509Store* CertManager::certStore()
{
    return store_.get();
}

} // namespace snet::crypto