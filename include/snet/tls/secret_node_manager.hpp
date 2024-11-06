#pragma once
#include <filesystem>
#include <optional>
#include <unordered_map>
#include <snet/tls/client_random.hpp>
#include <snet/tls/secret_node.hpp>
#include <snet/utils/noncopyable.hpp>

namespace snet::tls
{

class SecretNodeManager final : public utils::NonCopyable
{
public:
    SecretNodeManager();

    ~SecretNodeManager() noexcept;

    void addSecrets(const ClientRandom& clientRandom, SecretNode&& secretNode);

    std::optional<Secret> findSecret(const ClientRandom& clientRandom,
                                     const SecretNode::Type type);

    std::optional<SecretNode> getSecretNode(const ClientRandom& clientRandom);

    void parseKeyLogFile(const std::filesystem::path& keylog);

private:
    std::unordered_map<ClientRandom, SecretNode> container_;
};

} // namespace snet::tls
