#include <fstream>

#include <snet/utils/format.hpp>
#include <snet/utils/hexlify.hpp>
#include <snet/utils/string.hpp>
#include <snet/utils/exception.hpp>

#include <snet/tls/secret_node_manager.hpp>

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
    utils::ThrowIfFalse(
        std::filesystem::is_regular_file(keylog),
        utils::format("invalid file path '{}'", keylog.c_str()));

    std::ifstream stream(keylog.c_str());
    utils::ThrowIfFalse(stream.is_open(),
                        utils::format("failed to open '{}'", keylog.c_str()));

    std::string line{};
    std::size_t lineno{};

    SecretNode::Type type{};
    SecretNode secrets{};

    while (std::getline(stream, line))
    {
        lineno++;

        /* Skip white spaces and tabs on the left */
        utils::ltrim(line);

        /* Skip comments */
        auto pos = line.find_first_of("#");
        if (pos != std::string::npos)
        {
            line = line.substr(0, pos);
        }

        /* Skip white spaces and tabs on the right */
        utils::rtrim(line);

        /* Skip empty lines */
        if (line[0] == '\0' || line[0] == '\r' || line[0] == '\n')
        {
            continue;
        }

        auto params = utils::split(line, " ");
        utils::ThrowIfFalse(
            params.size() == 3,
            utils::format("invalid line #{}: {}", lineno, line));

        if (utils::iequals(params[0], "CLIENT_RANDOM"))
        {
            type = SecretNode::MasterSecret;
        }
        else if (utils::iequals(params[0], "CLIENT_EARLY_TRAFFIC_SECRET"))
        {
            type = SecretNode::ClientEarlyTrafficSecret;
        }
        else if (utils::iequals(params[0], "CLIENT_HANDSHAKE_TRAFFIC_SECRET"))
        {
            type = SecretNode::ClientHandshakeTrafficSecret;
        }
        else if (utils::iequals(params[0], "SERVER_HANDSHAKE_TRAFFIC_SECRET"))
        {
            type = SecretNode::ServerHandshakeTrafficSecret;
        }
        else if (utils::iequals(params[0], "CLIENT_TRAFFIC_SECRET_0"))
        {
            type = SecretNode::ClientTrafficSecret;
        }
        else if (utils::iequals(params[0], "SERVER_TRAFFIC_SECRET_0"))
        {
            type = SecretNode::ServerTrafficSecret;
        }
        else
        {
            /* Unrecognized secret type */
            continue;
        }

        auto clientRandom = utils::unhexlify(params[1]);
        auto secret = utils::unhexlify(params[2]);

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