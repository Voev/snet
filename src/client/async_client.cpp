#include <vector>
#include <iostream>
#include <iterator>
#include <openssl/err.h>
#include <snet/ossl_types.hpp>
#include <snet/socket.hpp>
#include <snet/ssl_context.hpp>
#include <snet/ssl_handle.hpp>

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        printf("usage %s <host> <port>\n", argv[0]);
        return 0;
    }
    try
    {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                             OPENSSL_INIT_LOAD_SSL_STRINGS,
                         nullptr);

        std::vector<std::thread> threads;
        for (int i = 0; i < 100; ++i)
        {
            threads.emplace_back([&]() {
                ConnectSocket sock;
                AddressIPv4 a{argv[1], (uint16_t)std::stoi(argv[2])};
                sock.Connect(a);

                SslContext ctx(TLS_client_method());
                SslClientHandle ssl(ctx, sock);
                ssl.Connect();
                SleepMs(1);
                ssl.Write("Some Data");
                std::vector<char> buff(1024);
                auto size = ssl.Read(buff.data(), buff.size());

                buff.resize(size);
                std::copy(std::begin(buff), std::end(buff),
                          std::ostream_iterator<char>(std::cout));
                ssl.Shutdown();
            });
        }
        for (auto& t : threads)
        {
            t.join();
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
