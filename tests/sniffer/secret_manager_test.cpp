#include <gtest/gtest.h>
#include <snet/tls/secret_node_manager.hpp>

using namespace snet::tls;

TEST(DISABLED_SecretManagerTest, Constructor)
{
    SecretNodeManager manager;
    manager.parseKeyLogFile("logfile.txt");
    manager.findSecret({0x00}, SecretNode::MasterSecret);
}
