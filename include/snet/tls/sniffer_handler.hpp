#pragma once
#include <snet/tls/i_record_handler.hpp>
#include <snet/tls/secret_node_manager.hpp>
#include <snet/tls/session.hpp>

namespace snet::tls
{

class SnifferHandler final : public IRecordHandler
{
public:
    explicit SnifferHandler(SecretNodeManager& secretNodeManager)
        : secretNodeManager_(secretNodeManager)
    {
    }

    void handleClientHello(const ClientHello& clientHello, Session* session) override
    {
        ClientRandom random{clientHello.random.begin(), clientHello.random.end()};
        auto secrets = secretNodeManager_.getSecretNode(random);
        if (secrets.has_value())
        {
            session->setSecrets(secrets.value());
        }
    }

    SecretNodeManager& secretNodeManager_;
};

} // namespace snet::tls
