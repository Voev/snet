#include <snet/crypto/exception.hpp>
#include <snet/crypto/pointers.hpp>

#include <snet/tls/key_share.hpp>
#include <snet/tls/record_encryptor.hpp>
#include <snet/tls/cipher_suite_manager.hpp>

#include <snet/tls/group_params.hpp>

#include <snet/utils/print_hex.hpp>

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
        if (session->getCipherState(sideIndex) && !session->canDecrypt(sideIndex))
        {
            return;
        }

        switch (record->handshake.type)
        {
        case HandshakeType::ClientHello:
            processHandshakeClientHello(sideIndex, session, record);
            break;
        default:
            break;
        }
    }
}

void RecordEncryptor::processHandshakeClientHello(const int8_t sideIndex, Session* session, Record* record)
{
    ::utils::ThrowIfFalse(sideIndex == 0, "Incorrect side index");

    record->handshake.clientHello.print(std::cout);

    auto supportedVersions = record->handshake.clientHello.extensions.get<SupportedVersions>();
    if (supportedVersions && supportedVersions->supports(ProtocolVersion::TLSv1_3))
    {
        auto keyShare = record->handshake.clientHello.extensions.get<KeyShare>();
        ::utils::ThrowIfFalse(keyShare != nullptr, "key_share extension not specified for TLSv1.3");

        auto groupNames = keyShare->offered_groups();

        for(size_t i = 0; i < groupNames.size(); ++i)
        {
            auto key = GenerateKeyByGroupParams(groupNames[i]);
            keyShare->setPublicKey(i, key);
        }
    }

    record->handshake.clientHello.print(std::cout);
    session->sendingLength = record->pack(session->sendingBuffer);

    utils::printHex(std::cout, "ClientHello", {session->sendingBuffer, session->sendingLength});
}

} // namespace snet::tls