#pragma once
#include <snet/tls/msgs/client_hello.hpp>
#include <snet/tls/msgs/server_hello.hpp>
#include <snet/tls/msgs/encrypted_extensions.hpp>

namespace snet::tls
{

struct HandshakeMessages
{
    ClientHello clientHello;
    ServerHello serverHello;
    EncryptedExtensions encryptedExtensions;
};

} // namespace snet::tls