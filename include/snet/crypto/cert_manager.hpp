#pragma once
#include <filesystem>
#include <snet/crypto/pointers.hpp>
#include <snet/utils/noncopyable.hpp>

namespace snet::crypto
{

class CertManager final : public utils::NonCopyable
{
public:
    CertManager();

    ~CertManager() noexcept;

    CertManager& addCA(Cert* cert);

    CertManager& addCRL(Crl* crl);

    CertManager& loadFile(const std::filesystem::path& path);

    CertManager& loadDirectory(const std::filesystem::path& path);

    CertManager& loadStore(std::string_view uri);

    CertStore* certStore();

private:
    CertStorePtr store_;
};

} // namespace snet::crypto