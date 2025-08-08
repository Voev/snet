#pragma once
#include <variant>
#include <snet/tls/msgs/client_hello.hpp>
#include <snet/tls/msgs/server_hello.hpp>
#include <snet/tls/msgs/encrypted_extensions.hpp>
#include <snet/tls/msgs/server_key_exchange.hpp>
#include <snet/tls/msgs/certificate.hpp>
#include <snet/tls/msgs/certificate_verify.hpp>
#include <snet/tls/msgs/finished.hpp>

namespace snet::tls
{

using Messages = std::variant<ClientHello, ServerHello, EncryptedExtensions, ServerKeyExchange, Certificate,
                              CertificateVerify, Finished>;

} // namespace snet::tls