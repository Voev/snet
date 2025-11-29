/// @file
/// @brief Declaration of the SecretNodeManager class.

#pragma once
#include <filesystem>
#include <optional>
#include <unordered_map>
#include <snet/tls/client_random.hpp>
#include <snet/tls/secret_node.hpp>
#include <casket/utils/noncopyable.hpp>

namespace snet::tls
{

/// @brief Class for managing secret nodes.
class SecretNodeManager final : public casket::NonCopyable
{
public:
    /// @brief Default constructor.
    SecretNodeManager();

    /// @brief Destructor.
    ~SecretNodeManager() noexcept;

    /// @brief Adds secrets to the manager.
    /// @param clientRandom The client's random value.
    /// @param secretNode The secret node to add.
    void addSecrets(const ClientRandom& clientRandom, SecretNode&& secretNode);

    /// @brief Finds a secret by client random and type.
    /// @param clientRandom The client's random value.
    /// @param type The type of the secret.
    /// @return An optional containing the secret if found, otherwise std::nullopt.
    std::optional<crypto::Secret> findSecret(const ClientRandom& clientRandom, const SecretNode::Type type);

    /// @brief Gets a secret node by client random.
    /// @param clientRandom The client's random value.
    /// @return An optional containing the secret node if found, otherwise std::nullopt.
    std::optional<SecretNode> getSecretNode(const ClientRandom& clientRandom);

    /// @brief Parses a key log file and adds the secrets to the manager.
    /// @param keylog The path to the key log file.
    void parseKeyLogFile(const std::filesystem::path& keylog);

private:
    std::unordered_map<ClientRandom, SecretNode> container_;
};

} // namespace snet::tls
