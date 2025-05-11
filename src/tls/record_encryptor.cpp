#include <snet/crypto/exception.hpp>
#include <snet/crypto/pointers.hpp>

#include <snet/tls/exchange.hpp>
#include <snet/tls/prf.hpp>
#include <snet/tls/key_share.hpp>
#include <snet/tls/record_encryptor.hpp>
#include <snet/tls/cipher_suite_manager.hpp>
#include <snet/tls/group_params.hpp>

#include <snet/utils/print_hex.hpp>

#include <casket/utils/exception.hpp>
#include <casket/utils/format.hpp>

#include <openssl/core_names.h>

using namespace casket;
using namespace snet::crypto;

namespace snet::tls
{

void RecordEncryptor::handleRecord(const int8_t sideIndex, Session* session, Record* record)
{
    ::utils::ThrowIfTrue(session == nullptr, "Session is not setted");

    if (record->type == RecordType::Handshake)
    {
        switch (session->handshake.type)
        {
        case HandshakeType::ClientHello:
            processHandshakeClientHello(sideIndex, session, record);
            break;
        case HandshakeType::ServerHello:
            processHandshakeServerHello(sideIndex, session, record);
            break;
        default:
            break;
        }
    }
}

void RecordEncryptor::processHandshakeClientHello(const int8_t sideIndex, Session* session, Record*)
{
    ::utils::ThrowIfFalse(sideIndex == 0, "Incorrect side index");

    session->handshake.clientHello.print(std::cout);

    auto supportedVersions = session->handshake.clientHello.extensions.get<SupportedVersions>();
    if (supportedVersions && supportedVersions->supports(ProtocolVersion::TLSv1_3))
    {
        auto keyShare = session->handshake.clientHello.extensions.get<KeyShare>();
        ::utils::ThrowIfFalse(keyShare != nullptr, "key_share extension not specified for TLSv1.3");

        auto groupNames = keyShare->offered_groups();

        for (size_t i = 0; i < groupNames.size(); ++i)
        {
            session->ephemeralKey = GenerateKeyByGroupParams(groupNames[i]);
            keyShare->setPublicKey(i, session->ephemeralKey);
            /// @todo: fix for all keys
            break;
        }
    }

    auto outputRecord = recordPool_.acquire();

    auto msgSize = outputRecord->pack(session->handshake, outputRecord->payloadBuffer);

    session->updateHash(1, {outputRecord->payloadBuffer.data() + TLS_HEADER_SIZE, msgSize - TLS_HEADER_SIZE});

    session->writingRecords_.push(outputRecord);
}

void RecordEncryptor::processHandshakeServerHello(const int8_t sideIndex, Session* session, Record* record)
{
    ::utils::ThrowIfFalse(sideIndex == 1, "Incorrect side index");

    if (session->getVersion() == ProtocolVersion::TLSv1_3)
    {
        auto serverKeyShare = session->handshake.serverHello.extensions.get<KeyShare>();
        ::utils::ThrowIfTrue(serverKeyShare == nullptr, "'key_share' extension from server not found");

        auto serverExchangedSecret = ExchangeSecret(session->ephemeralKey, serverKeyShare->getPublicKey(), true);
        
        session->generateHandshakeSecrets(1, serverExchangedSecret);
        
        auto clientKeyShare = session->handshake.clientHello.extensions.get<KeyShare>();
        ::utils::ThrowIfTrue(clientKeyShare == nullptr, "'key_share' extension from client not found");
    
        auto groups = clientKeyShare->offered_groups();
        auto serverGroupParams = serverKeyShare->selected_group();
        size_t i = 0;

        for (i = 0; i < groups.size(); ++i)
        {
            if (groups[i] == serverGroupParams)
            {
                break;
            }
        }
        ::utils::ThrowIfTrue(i == groups.size(), "common group params not found");

        auto clientExchangedSecret = ExchangeSecret(session->ephemeralKey, clientKeyShare->getPublicKey(i), true);
        session->generateHandshakeSecrets(0, clientExchangedSecret);
    }

    session->sendingLength = record->pack(session->handshake, session->sendingBuffer);

}

} // namespace snet::tls