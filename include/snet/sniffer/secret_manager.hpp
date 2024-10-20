#pragma once
#include <filesystem>
#include <optional>
#include <unordered_map>
#include <snet/sniffer/client_random.hpp>
#include <snet/sniffer/secret_keys.hpp>
#include <snet/utils/noncopyable.hpp>

namespace snet::sniffer
{

class SecretManager final : public utils::NonCopyable
{
public:
    SecretManager();

    ~SecretManager() noexcept;

    void addSecrets(const ClientRandom& clientRandom, SecretKeys&& secrets);

    std::optional<Secret> findSecret(const ClientRandom& clientRandom,
                                     const SecretKeys::Type type);

    void parseKeyLogFile(const std::filesystem::path& keylog);

private:
    std::unordered_map<ClientRandom, SecretKeys> container_;
};

} // namespace snet::sniffer
