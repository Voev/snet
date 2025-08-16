#include <gtest/gtest.h>
#include <snet/layers/packet.hpp>

using namespace snet::layers;

TEST(PacketTest, Constructor)
{
    Packet packet;
    Packet packet2 = packet;
}
