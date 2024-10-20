#pragma once
#include <list>
#include <snet/sniffer/server_info.hpp>

namespace snet::sniffer
{

class ServerManager
{
public:

private:
    std::list<ServerInfo> infos_;
};


}