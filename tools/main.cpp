#include <iostream>
#include <snet/ip/ip_address.hpp>
#include <snet/socket/socket.hpp>
#include <snet/socket/tcp.hpp>
#include <snet/tls/connection.hpp>
#include <snet/log/log_manager.hpp>

int main()
{
    snet::log::LogManager::Instance().enable(snet::log::Type::Console);
    snet::log::LogManager::Instance().setLevel(snet::log::Level::Debug);

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
        snet::log::emergency("OK");
        snet::log::critical("OK");
        snet::log::alert("OK");
        snet::log::error("OK");
        snet::log::warning("OK");
        snet::log::notice("OK");
        snet::log::info("OK");
        snet::log::debug("OK");
    }
    return EXIT_SUCCESS;
}