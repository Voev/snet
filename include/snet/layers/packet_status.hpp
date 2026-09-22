#pragma once

namespace snet::layers
{

enum PacketStatus
{
    UnknownStatus = 0,
    PacketHandled,
    Error_NoContext,
    Error_NoMemory,
    TcpMessageHandled,
    OutOfOrderTcpMessageBuffered,
    FIN_RSTWithNoData,
    Ignore_PacketWithNoData,
    Ignore_PacketOfClosedFlow,
    Ignore_Retransimission,
    NonIpPacket,
    NonTcpPacket,
    Error_PacketDoesNotMatchFlow,
};

}