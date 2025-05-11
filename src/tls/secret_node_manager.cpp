#include <fstream>

#include <casket/utils/string.hpp>
#include <casket/utils/format.hpp>
#include <casket/utils/hexlify.hpp>
#include <casket/utils/exception.hpp>

#include <snet/tls/secret_node_manager.hpp>

using namespace casket::utils;

namespace snet::tls
{

SecretNodeManager::SecretNodeManager() = default;

SecretNodeManager::~SecretNodeManager() noexcept = default;

void SecretNodeManager::addSecrets(const ClientRandom& clientRandom,
                                   SecretNode&& secretNode)
{
    container_.insert(std::make_pair(clientRandom, std::move(secretNode)));
}

std::optional<Secret>
SecretNodeManager::findSecret(const ClientRandom& clientRandom,
                              const SecretNode::Type type)
{
    auto found = container_.find(clientRandom);
    if (found != container_.end())
    {
        return found->second.getSecret(type);
    }
    return std::nullopt;
}

std::optional<SecretNode>
SecretNodeManager::getSecretNode(const ClientRandom& clientRandom)
{
    auto found = container_.find(clientRandom);
    if (found != container_.end())
    {
        return found->second;
    }
    return std::nullopt;
}

void SecretNodeManager::parseKeyLogFile(const std::filesystem::path& keylog)
{
    ThrowIfFalse(
        std::filesystem::is_regular_file(keylog),
        format("invalid file path '{}'", keylog.c_str()));

    std::ifstream stream(keylog.c_str());
    ThrowIfFalse(stream.is_open(),
                        format("failed to open '{}'", keylog.c_str()));

    std::string line{};
    std::size_t lineno{};

    SecretNode::Type type{};
    SecretNode secrets{};

    while (std::getline(stream, line))
    {
        lineno++;

        /* Skip white spaces and tabs on the left */
        ltrim(line);

        /* Skip comments */
        auto pos = line.find_first_of("#");
        if (pos != std::string::npos)
        {
            line = line.substr(0, pos);
        }

        /* Skip white spaces and tabs on the right */
        rtrim(line);

        /* Skip empty lines */
        if (line[0] == '\0' || line[0] == '\r' || line[0] == '\n')
        {
            continue;
        }

        auto params = split(line, " ");
        ThrowIfFalse(
            params.size() == 3,
            format("invalid line #{}: {}", lineno, line));

        if (iequals(params[0], "CLIENT_RANDOM"))
        {
            type = SecretNode::MasterSecret;
        }
        else if (iequals(params[0], "CLIENT_EARLY_TRAFFIC_SECRET"))
        {
            type = SecretNode::ClientEarlyTrafficSecret;
        }
        else if (iequals(params[0], "CLIENT_HANDSHAKE_TRAFFIC_SECRET"))
        {
            type = SecretNode::ClientHandshakeTrafficSecret;
        }
        else if (iequals(params[0], "SERVER_HANDSHAKE_TRAFFIC_SECRET"))
        {
            type = SecretNode::ServerHandshakeTrafficSecret;
        }
        else if (iequals(params[0], "CLIENT_TRAFFIC_SECRET_0"))
        {
            type = SecretNode::ClientApplicationTrafficSecret;
        }
        else if (iequals(params[0], "SERVER_TRAFFIC_SECRET_0"))
        {
            type = SecretNode::ServerApplicationTrafficSecret;
        }
        else
        {
            /* Unrecognized secret type */
            continue;
        }

        auto clientRandom = unhexlify(params[1]);
        auto secret = unhexlify(params[2]);

        auto found = container_.find(clientRandom);
        if (found != container_.end())
        {
            found->second.setSecret(type, secret);
        }
        else
        {
            auto pair = container_.insert_or_assign(clientRandom, SecretNode());
            pair.first->second.setSecret(type, secret);
        }
    }

    stream.close();
}

} // namespace snet::tls