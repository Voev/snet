#include <vector>
#include <algorithm>
#include <iostream>
#include <iterator>
#include <openssl/err.h>
#include <snet/ossl_types.hpp>
#include <snet/socket.hpp>
#include <snet/ssl_context.hpp>
#include <snet/ssl_handle.hpp>
#include <snet/event_manager.hpp>

int main(int argc, char* argv[])
{
    std::vector<std::string> arguments(argv + 1, argv + argc);
    try
    {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                             OPENSSL_INIT_LOAD_SSL_STRINGS,
                         nullptr);
        auto sock = std::make_unique<AcceptSocket>();

        AddressIPv4 a{arguments.at(0),
                      static_cast<uint16_t>(std::stoi(arguments.at(1)))};
        sock->Listen(a);

        auto ctx = std::make_unique<SslContext>(TLS_server_method());
        ctx->LoadCertificate("server.pem");
        ctx->LoadPrivateKey("server.pem");
        if (std::find(arguments.begin(), arguments.end(), "-t") !=
            arguments.end())
        {

            ctx->EnableTlsTrace();
        }
        ctx->SetMaxVersion(TLS1_2_VERSION);

        EventManager manager{std::move(sock), std::move(ctx)};
        manager.MainThread(-1);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}