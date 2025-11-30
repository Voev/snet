#include <fstream>

#include <snet/tls/secret_node_manager.hpp>

#include <casket/utils/string.hpp>
#include <casket/utils/format.hpp>
#include <casket/utils/hexlify.hpp>
#include <casket/utils/exception.hpp>

namespace snet::tls
{

SecretNodeManager::SecretNodeManager() = default;

SecretNodeManager::~SecretNodeManager() noexcept = default;

void SecretNodeManager::addSecrets(const ClientRandom& clientRandom, SecretNode&& secretNode)
{
    container_.insert(std::make_pair(clientRandom, std::move(secretNode)));
}

std::optional<SecretNode> SecretNodeManager::getSecretNode(const ClientRandom& clientRandom)
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
    casket::ThrowIfFalse(std::filesystem::is_regular_file(keylog),
                         casket::format("invalid file path '{}'", keylog.c_str()));

    std::ifstream stream(keylog.c_str());
    casket::ThrowIfFalse(stream.is_open(), casket::format("failed to open '{}'", keylog.c_str()));

    std::string line{};
    std::size_t lineno{};

    while (std::getline(stream, line))
    {
        lineno++;

        /* Skip white spaces and tabs on the left */
        casket::ltrim(line);

        /* Skip comments */
        auto pos = line.find_first_of("#");
        if (pos != std::string::npos)
        {
            line = line.substr(0, pos);
        }

        /* Skip white spaces and tabs on the right */
        casket::rtrim(line);

        /* Skip empty lines */
        if (line[0] == '\0' || line[0] == '\r' || line[0] == '\n')
        {
            continue;
        }

        auto params = casket::split(line, " ");
        casket::ThrowIfFalse(params.size() == 3, casket::format("invalid line #{}: {}", lineno, line));

        auto clientRandom = casket::unhexlify(params[1]);
        auto secret = casket::unhexlify(params[2]);

        auto found = container_.find(clientRandom);
        if (found == container_.end())
        {
            auto pair = container_.insert_or_assign(clientRandom, SecretNode());
            found = pair.first;
        }

        if (casket::iequals(params[0], "CLIENT_RANDOM"))
        {
            found->second.masterSecret = std::move( secret );
        }
        else if (casket::iequals(params[0], "CLIENT_EARLY_TRAFFIC_SECRET"))
        {
            found->second.clientEarlyTrafficSecret = std::move( secret );
        }
        else if (casket::iequals(params[0], "CLIENT_HANDSHAKE_TRAFFIC_SECRET"))
        {
            found->second.clientHndTrafficSecret = std::move( secret );
        }
        else if (casket::iequals(params[0], "SERVER_HANDSHAKE_TRAFFIC_SECRET"))
        {
            found->second.serverHndTrafficSecret = std::move( secret );
        }
        else if (casket::iequals(params[0], "CLIENT_TRAFFIC_SECRET_0"))
        {
            found->second.clientAppTrafficSecret = std::move( secret );
        }
        else if (casket::iequals(params[0], "SERVER_TRAFFIC_SECRET_0"))
        {
            found->second.serverAppTrafficSecret = std::move( secret );
        }
        else
        {
            /* Unrecognized secret type */
            continue;
        }
    }

    stream.close();
}

} // namespace snet::tls