#pragma once
#include <snet/tls/msgs/client_hello.hpp>
#include <snet/tls/msgs/server_hello.hpp>
#include <snet/tls/msgs/encrypted_extensions.hpp>
#include <snet/tls/msgs/server_key_exchange.hpp>
#include <snet/tls/msgs/certificate.hpp>
#include <snet/tls/msgs/finished.hpp>

namespace snet::tls
{

struct HandshakeMessages
{
    //ClientHello clientHello;
    //ServerHello serverHello;
    EncryptedExtensions encryptedExtensions;
    //ServerKeyExchange serverKeyExchange;
    Certificate serverCertificate;
    //Finished clientFinished;
    //Finished serverFinished;
};

} // namespace snet::tls