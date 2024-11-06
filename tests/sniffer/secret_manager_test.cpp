#include <gtest/gtest.h>
#include <snet/sniffer/secret_manager.hpp>

using namespace snet::sniffer;

TEST(DISABLED_SecretManagerTest, Constructor)
{
    SecretManager manager;
    manager.parseKeyLogFile("logfile.txt");
    manager.findSecret({0x00}, SecretKeys::MasterSecret);
}
