#include <iostream>
#include <snet/ip/ip_address.hpp>
#include <snet/socket/socket.hpp>
#include <snet/socket/tcp.hpp>
#include <snet/tls/connection.hpp>

int main()
{
    snet::socket::Socket s;
    s.open(snet::socket::Tcp::v4());
    auto ip = snet::ip::IPAddress::fromString("5.255.255.242");
    s.connect(snet::socket::Endpoint(ip.value(), 443));

    snet::tls::ClientSettings settings;
    snet::tls::Connection conn(settings);

    conn.setSocket(s.get());
    auto want = conn.handshake();
    if(want == snet::tls::Connection::Want::Nothing)
    {
        std::cout << "OK" << std::endl;
    }
    return EXIT_SUCCESS;
}