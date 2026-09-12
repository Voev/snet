// tests/tcp_fsm_test.cpp

#include <gtest/gtest.h>

#include <optional>
#include <vector>
#include <cstring>
#include <chrono>

#include <snet/tcp/tcp_state.hpp>
#include <snet/tcp/tcp_connection.hpp>
#include <snet/tcp/tcp_state_machine.hpp>
#include <snet/layers/l3/ip_address.hpp>

using namespace snet::tcp;
using namespace snet::layers;

namespace
{

IPAddress ip(const char* s)
{
    auto opt = IPAddress::fromString(s);
    EXPECT_TRUE(opt.has_value()) << "failed to parse IP: " << s;
    return opt.value();
}

TcpConnection makeConnection()
{
    TcpConnection c;
    c.localIP = ip("127.0.0.1");
    c.remoteIP = ip("127.0.0.1");
    c.localPort = 12345;
    c.remotePort = 80;
    return c;
}

TcpSegment makeSeg(TcpFlags f, uint32_t seq, uint32_t ack, uint16_t win = 65535, const uint8_t* data = nullptr,
                   size_t len = 0)
{
    TcpSegment s;
    s.flags = f;
    s.seq = seq;
    s.ack = ack;
    s.window = win;
    s.payload = data;
    s.payloadLen = len;
    return s;
}

const uint8_t kPayload[] = "hello";

} // namespace

TEST(IPAddressFromStringTest, ParsesIpv4)
{
    auto opt = IPAddress::fromString("192.168.1.1");
    ASSERT_TRUE(opt.has_value());
}

TEST(IPAddressFromStringTest, ParsesIpv6)
{
    auto opt = IPAddress::fromString("::1");
    ASSERT_TRUE(opt.has_value());
}

TEST(IPAddressFromStringTest, RejectsInvalid)
{
    auto opt = IPAddress::fromString("not-an-ip");
    EXPECT_FALSE(opt.has_value());
}

TEST(TcpStateNameTest, AllStatesHaveNames)
{
    EXPECT_EQ(tcpStateName(TcpState::Closed), "CLOSED");
    EXPECT_EQ(tcpStateName(TcpState::Listen), "LISTEN");
    EXPECT_EQ(tcpStateName(TcpState::SynSent), "SYN_SENT");
    EXPECT_EQ(tcpStateName(TcpState::SynReceived), "SYN_RECEIVED");
    EXPECT_EQ(tcpStateName(TcpState::Established), "ESTABLISHED");
    EXPECT_EQ(tcpStateName(TcpState::FinWait1), "FIN_WAIT_1");
    EXPECT_EQ(tcpStateName(TcpState::FinWait2), "FIN_WAIT_2");
    EXPECT_EQ(tcpStateName(TcpState::CloseWait), "CLOSE_WAIT");
    EXPECT_EQ(tcpStateName(TcpState::Closing), "CLOSING");
    EXPECT_EQ(tcpStateName(TcpState::LastAck), "LAST_ACK");
    EXPECT_EQ(tcpStateName(TcpState::TimeWait), "TIME_WAIT");
}

TEST(TcpStateNameTest, UnknownState)
{
    EXPECT_EQ(tcpStateName(static_cast<TcpState>(255)), "UNKNOWN");
}

TEST(TcpFlagsTest, FromByteAllBits)
{
    auto f = TcpFlags::fromByte(0x3F);
    EXPECT_TRUE(f.fin);
    EXPECT_TRUE(f.syn);
    EXPECT_TRUE(f.rst);
    EXPECT_TRUE(f.psh);
    EXPECT_TRUE(f.ack);
    EXPECT_TRUE(f.urg);
}

TEST(TcpFlagsTest, FromByteNone)
{
    auto f = TcpFlags::fromByte(0x00);
    EXPECT_FALSE(f.fin);
    EXPECT_FALSE(f.syn);
    EXPECT_FALSE(f.rst);
    EXPECT_FALSE(f.psh);
    EXPECT_FALSE(f.ack);
    EXPECT_FALSE(f.urg);
}

TEST(TcpFlagsTest, FromByteIndividualBits)
{
    EXPECT_TRUE(TcpFlags::fromByte(0x01).fin);
    EXPECT_TRUE(TcpFlags::fromByte(0x02).syn);
    EXPECT_TRUE(TcpFlags::fromByte(0x04).rst);
    EXPECT_TRUE(TcpFlags::fromByte(0x08).psh);
    EXPECT_TRUE(TcpFlags::fromByte(0x10).ack);
    EXPECT_TRUE(TcpFlags::fromByte(0x20).urg);
}

TEST(TcpOutputTest, Factories)
{
    auto none = TcpOutput::none();
    EXPECT_EQ(none.type, TcpOutput::Type::None);

    auto s = TcpOutput::send({.syn = true}, 1, 2, 3, kPayload, 5);
    EXPECT_EQ(s.type, TcpOutput::Type::Send);
    EXPECT_TRUE(s.flags.syn);
    EXPECT_EQ(s.seq, 1u);
    EXPECT_EQ(s.ack, 2u);
    EXPECT_EQ(s.window, 3u);
    EXPECT_EQ(s.payload, kPayload);
    EXPECT_EQ(s.payloadLen, 5u);

    auto r = TcpOutput::reset(10, 20);
    EXPECT_EQ(r.type, TcpOutput::Type::SendReset);
    EXPECT_TRUE(r.flags.rst);
    EXPECT_TRUE(r.flags.ack);
    EXPECT_EQ(r.seq, 10u);
    EXPECT_EQ(r.ack, 20u);

    auto c = TcpOutput::close();
    EXPECT_EQ(c.type, TcpOutput::Type::Close);
}

TEST(TcpConnectionTest, InEstablishedAndTerminal)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    EXPECT_TRUE(c.inEstablished());
    c.state = TcpState::FinWait1;
    EXPECT_TRUE(c.inEstablished());
    c.state = TcpState::FinWait2;
    EXPECT_TRUE(c.inEstablished());
    c.state = TcpState::CloseWait;
    EXPECT_TRUE(c.inEstablished());
    c.state = TcpState::Closing;
    EXPECT_TRUE(c.inEstablished());
    c.state = TcpState::LastAck;
    EXPECT_TRUE(c.inEstablished());
    c.state = TcpState::Closed;
    EXPECT_FALSE(c.inEstablished());
    EXPECT_TRUE(c.isTerminal());
    c.state = TcpState::TimeWait;
    EXPECT_TRUE(c.isTerminal());
    c.state = TcpState::Established;
    EXPECT_FALSE(c.isTerminal());
}

TEST(TcpConnectionTest, ResetClearsFields)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    c.sndUna = 10;
    c.sndNxt = 20;
    c.iss = 5;
    c.packetsReceived = 7;
    c.reset();
    EXPECT_EQ(c.state, TcpState::Closed);
    EXPECT_EQ(c.sndUna, 0u);
    EXPECT_EQ(c.sndNxt, 0u);
    EXPECT_EQ(c.packetsReceived, 0u);
}

TEST(TcpFsmTest, ActiveOpenSendsSyn)
{
    TcpConnection c = makeConnection();
    auto out = TcpStateMachine::onActiveOpen(c, 1000);
    EXPECT_EQ(c.state, TcpState::SynSent);
    EXPECT_EQ(out.type, TcpOutput::Type::Send);
    EXPECT_TRUE(out.flags.syn);
    EXPECT_FALSE(out.flags.ack);
    EXPECT_EQ(out.seq, 1000u);
    EXPECT_EQ(c.iss, 1000u);
    EXPECT_EQ(c.sndUna, 1000u);
    EXPECT_EQ(c.sndNxt, 1000u);
}

TEST(TcpFsmTest, ActiveOpenIgnoredIfNotClosed)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    auto out = TcpStateMachine::onActiveOpen(c, 1000);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
}

TEST(TcpFsmTest, PassiveOpenSendsSynAck)
{
    TcpConnection c = makeConnection();
    auto out = TcpStateMachine::onPassiveOpen(c, ip("10.0.0.1"), 80, ip("10.0.0.2"), 5000, 500, 9000);
    EXPECT_EQ(c.state, TcpState::SynReceived);
    EXPECT_TRUE(c.passiveOpen);
    EXPECT_EQ(c.irs, 500u);
    EXPECT_EQ(c.rcvNxt, 501u);
    EXPECT_EQ(c.iss, 9000u);
    EXPECT_EQ(out.type, TcpOutput::Type::Send);
    EXPECT_TRUE(out.flags.syn);
    EXPECT_TRUE(out.flags.ack);
    EXPECT_EQ(out.seq, 9000u);
    EXPECT_EQ(out.ack, 501u);
}

TEST(TcpFsmTest, PassiveOpenIgnoredIfNotClosed)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    auto out = TcpStateMachine::onPassiveOpen(c, ip("10.0.0.1"), 80, ip("10.0.0.2"), 5000, 1, 2);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
}

TEST(TcpFsmTest, AppSendInEstablished)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onActiveOpen(c, 100);
    c.state = TcpState::Established;
    c.sndWnd = 65535;
    c.cwnd = 10;

    auto out = TcpStateMachine::onAppSend(c, kPayload, 5);
    EXPECT_EQ(out.type, TcpOutput::Type::Send);
    EXPECT_TRUE(out.flags.psh);
    EXPECT_TRUE(out.flags.ack);
    EXPECT_EQ(out.payloadLen, 5u);
}

TEST(TcpFsmTest, AppSendNotEstablished)
{
    TcpConnection c = makeConnection();
    auto out = TcpStateMachine::onAppSend(c, kPayload, 5);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
}

TEST(TcpFsmTest, AppSendZeroLength)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    auto out = TcpStateMachine::onAppSend(c, nullptr, 0);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
}

TEST(TcpFsmTest, AppSendZeroWindow)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    c.sndWnd = 0;
    c.cwnd = 0;
    auto out = TcpStateMachine::onAppSend(c, kPayload, 5);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
}

TEST(TcpFsmTest, AppCloseFromEstablished)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    auto out = TcpStateMachine::onAppClose(c);
    EXPECT_EQ(c.state, TcpState::FinWait1);
    EXPECT_TRUE(c.finSent);
    EXPECT_EQ(out.type, TcpOutput::Type::Send);
    EXPECT_TRUE(out.flags.fin);
    EXPECT_TRUE(out.flags.ack);
}

TEST(TcpFsmTest, AppCloseFromCloseWait)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::CloseWait;
    auto out = TcpStateMachine::onAppClose(c);
    EXPECT_EQ(c.state, TcpState::LastAck);
    EXPECT_TRUE(c.finSent);
    EXPECT_EQ(out.type, TcpOutput::Type::Send);
    EXPECT_TRUE(out.flags.fin);
}

TEST(TcpFsmTest, AppCloseIgnoredInOtherStates)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::SynSent;
    auto out = TcpStateMachine::onAppClose(c);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
}

TEST(TcpFsmTest, AppAbort)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    c.sndNxt = 100;
    c.rcvNxt = 200;
    auto out = TcpStateMachine::onAppAbort(c);
    EXPECT_EQ(c.state, TcpState::Closed);
    EXPECT_TRUE(c.resetSent);
    EXPECT_TRUE(c.closed);
    EXPECT_EQ(out.type, TcpOutput::Type::SendReset);
    EXPECT_TRUE(out.flags.rst);
    EXPECT_TRUE(out.flags.ack);
    EXPECT_EQ(out.seq, 100u);
    EXPECT_EQ(out.ack, 200u);
}

TEST(TcpFsmTest, RxRstClosesConnection)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.rst = true}, 0, 0));
    EXPECT_EQ(c.state, TcpState::Closed);
    EXPECT_TRUE(c.closed);
    EXPECT_TRUE(res.closed);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Close);
}

TEST(TcpFsmTest, RxInClosedWithAckSendsRst)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Closed;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 100, 200));
    EXPECT_EQ(res.output.type, TcpOutput::Type::SendReset);
    EXPECT_EQ(res.output.seq, 200u);
    EXPECT_EQ(res.output.ack, 0u);
}

TEST(TcpFsmTest, RxInClosedWithoutAckSendsRst)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Closed;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.syn = true}, 100, 0, 65535, kPayload, 5));
    EXPECT_EQ(res.output.type, TcpOutput::Type::SendReset);
    EXPECT_EQ(res.output.seq, 0u);
    EXPECT_EQ(res.output.ack, 106u);
}

TEST(TcpFsmTest, SynSentReceivesSynAck)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onActiveOpen(c, 1000);
    c.sndNxt = 1001;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.syn = true, .ack = true}, 5000, 1001));
    EXPECT_EQ(c.state, TcpState::Established);
    EXPECT_TRUE(res.connectionEstablished);
    EXPECT_EQ(c.irs, 5000u);
    EXPECT_EQ(c.rcvNxt, 5001u);
    EXPECT_EQ(c.sndUna, 1001u);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Send);
    EXPECT_TRUE(res.output.flags.ack);
}

TEST(TcpFsmTest, SynSentReceivesSynAckBadAck)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onActiveOpen(c, 1000);
    c.sndNxt = 1001;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.syn = true, .ack = true}, 5000, 9999));
    EXPECT_EQ(res.output.type, TcpOutput::Type::SendReset);
}

TEST(TcpFsmTest, SynSentReceivesSynOnly)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onActiveOpen(c, 1000);
    c.sndNxt = 1001;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.syn = true}, 5000, 0));
    EXPECT_EQ(c.state, TcpState::SynReceived);
    EXPECT_EQ(c.irs, 5000u);
    EXPECT_EQ(c.rcvNxt, 5001u);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Send);
    EXPECT_TRUE(res.output.flags.syn);
    EXPECT_TRUE(res.output.flags.ack);
}

TEST(TcpFsmTest, SynSentIgnoresOtherSegments)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onActiveOpen(c, 1000);
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 1, 1));
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
    EXPECT_EQ(c.state, TcpState::SynSent);
}

TEST(TcpFsmTest, SynReceivedAcceptsAck)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onPassiveOpen(c, ip("10.0.0.1"), 80, ip("10.0.0.2"), 5000, 500, 9000);
    c.sndNxt = 9001;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 501, 9001));
    EXPECT_EQ(c.state, TcpState::Established);
    EXPECT_TRUE(res.connectionEstablished);
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
}

TEST(TcpFsmTest, SynReceivedAcceptsAckWithData)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onPassiveOpen(c, ip("10.0.0.1"), 80, ip("10.0.0.2"), 5000, 500, 9000);
    c.sndNxt = 9001;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 501, 9001, 65535, kPayload, 5));
    EXPECT_EQ(c.state, TcpState::Established);
    EXPECT_TRUE(res.deliverToApp);
    EXPECT_EQ(c.rcvNxt, 506u);
    EXPECT_EQ(c.bytesReceived, 5u);
}

TEST(TcpFsmTest, SynReceivedRetransmittedSyn)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onPassiveOpen(c, ip("10.0.0.1"), 80, ip("10.0.0.2"), 5000, 500, 9000);
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.syn = true}, 500, 0));
    EXPECT_EQ(res.output.type, TcpOutput::Type::Send);
    EXPECT_TRUE(res.output.flags.syn);
    EXPECT_TRUE(res.output.flags.ack);
    EXPECT_EQ(res.output.seq, 9000u);
}

TEST(TcpFsmTest, SynReceivedUnexpectedSegmentSendsRst)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onPassiveOpen(c, ip("10.0.0.1"), 80, ip("10.0.0.2"), 5000, 500, 9000);
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 9999, 9999));
    EXPECT_EQ(res.output.type, TcpOutput::Type::SendReset);
}

TEST(TcpFsmTest, EstablishedProcessesData)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    c.rcvNxt = 100;
    c.sndNxt = 200;
    c.sndUna = 200;
    c.sndWnd = 65535;
    c.cwnd = 10;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 100, 200, 65535, kPayload, 5));
    EXPECT_TRUE(res.deliverToApp);
    EXPECT_EQ(c.rcvNxt, 105u);
    EXPECT_EQ(c.bytesReceived, 5u);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Send);
    EXPECT_TRUE(res.output.flags.ack);
}

TEST(TcpFsmTest, EstablishedProcessesOutOfOrderData)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    c.rcvNxt = 100;
    c.sndNxt = 200;
    c.sndUna = 200;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 200, 200, 65535, kPayload, 5));
    EXPECT_FALSE(res.deliverToApp);
    EXPECT_EQ(c.dupAcks, 1u);
}

TEST(TcpFsmTest, EstablishedProcessesRetransmit)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    c.rcvNxt = 200;
    c.sndNxt = 300;
    c.sndUna = 300;
    TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 197, 300, 65535, kPayload, 5));
    EXPECT_EQ(c.rcvNxt, 200u);
}

TEST(TcpFsmTest, EstablishedFinClosesToCloseWait)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    c.rcvNxt = 100;
    c.sndNxt = 200;
    c.sndUna = 200;
    TcpFlags flags;
    flags.ack = true;
    flags.fin = true;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg(flags, 100, 200));
    EXPECT_EQ(c.state, TcpState::CloseWait);
    EXPECT_TRUE(c.finReceived);
    EXPECT_EQ(c.rcvNxt, 101u);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Send);
    EXPECT_TRUE(res.output.flags.ack);
}

TEST(TcpFsmTest, EstablishedAckOnlyNoPendingData)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    c.rcvNxt = 100;
    c.sndNxt = 200;
    c.sndUna = 200;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 100, 200));
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
}

TEST(TcpFsmTest, EstablishedAckAdvancesSndUna)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onActiveOpen(c, 100);
    c.state = TcpState::Established;
    c.sndUna = 100;
    c.sndNxt = 200;
    c.rcvNxt = 500;
    c.ssthresh = 100;
    TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 500, 150, 1000));
    EXPECT_EQ(c.sndUna, 150u);
    EXPECT_EQ(c.sndWnd, 1000u);
}

TEST(TcpFsmTest, FinWait1AckTransitionsToFinWait2)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::FinWait1;
    c.sndNxt = 200;
    c.sndUna = 200;
    c.rcvNxt = 100;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 100, 200));
    EXPECT_EQ(c.state, TcpState::FinWait2);
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
}

TEST(TcpFsmTest, FinWait1AckWithFinTransitionsToClosing)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::FinWait1;
    c.sndNxt = 200;
    c.sndUna = 200;
    c.rcvNxt = 100;
    TcpFlags flags;
    flags.ack = true;
    flags.fin = true;

    auto res = TcpStateMachine::onRxSegment(c, makeSeg(flags, 100, 200));
    EXPECT_EQ(c.state, TcpState::Closing);
    EXPECT_TRUE(c.finReceived);
    EXPECT_EQ(c.rcvNxt, 101u);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Send);
    EXPECT_TRUE(res.output.flags.ack);
}

TEST(TcpFsmTest, FinWait1FinOnlySimultaneousClose)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::FinWait1;
    c.sndNxt = 200;
    c.sndUna = 200;
    c.rcvNxt = 100;
    TcpStateMachine::onRxSegment(c, makeSeg({.fin = true}, 100, 0));
    EXPECT_EQ(c.state, TcpState::Closing);
    EXPECT_TRUE(c.finReceived);
}

TEST(TcpFsmTest, FinWait1DataDelivery)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::FinWait1;
    c.sndNxt = 200;
    c.sndUna = 200;
    c.rcvNxt = 100;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 100, 200, 65535, kPayload, 5));
    EXPECT_TRUE(res.deliverToApp);
    EXPECT_EQ(c.rcvNxt, 105u);
}

TEST(TcpFsmTest, FinWait2FinTransitionsToTimeWait)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::FinWait2;
    c.rcvNxt = 100;
    c.sndNxt = 200;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.fin = true}, 100, 200));
    EXPECT_EQ(c.state, TcpState::TimeWait);
    EXPECT_TRUE(c.finReceived);
    EXPECT_EQ(c.rcvNxt, 101u);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Send);
    EXPECT_TRUE(res.output.flags.ack);
}

TEST(TcpFsmTest, FinWait2DataDelivery)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::FinWait2;
    c.rcvNxt = 100;
    c.sndNxt = 200;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 100, 200, 65535, kPayload, 5));
    EXPECT_TRUE(res.deliverToApp);
    EXPECT_EQ(c.rcvNxt, 105u);
}

TEST(TcpFsmTest, FinWait2NoDataNoFin)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::FinWait2;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 1, 1));
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
}

TEST(TcpFsmTest, CloseWaitIgnoresSegment)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::CloseWait;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 1, 1));
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
    EXPECT_EQ(c.state, TcpState::CloseWait);
}

TEST(TcpFsmTest, ClosingAckTransitionsToTimeWait)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Closing;
    c.sndNxt = 200;
    c.sndUna = 200;
    TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 1, 200));
    EXPECT_EQ(c.state, TcpState::TimeWait);
}

TEST(TcpFsmTest, ClosingNonMatchingAckIgnored)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Closing;
    c.sndNxt = 200;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 1, 999));
    EXPECT_EQ(c.state, TcpState::Closing);
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
}

TEST(TcpFsmTest, LastAckAckClosesConnection)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::LastAck;
    c.sndNxt = 200;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 1, 200));
    EXPECT_EQ(c.state, TcpState::Closed);
    EXPECT_TRUE(c.closed);
    EXPECT_TRUE(res.closed);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Close);
}

TEST(TcpFsmTest, LastAckNonMatchingAckIgnored)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::LastAck;
    c.sndNxt = 200;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 1, 999));
    EXPECT_EQ(c.state, TcpState::LastAck);
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
}

TEST(TcpFsmTest, TimeWaitFinResendsAck)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::TimeWait;
    c.sndNxt = 200;
    c.rcvNxt = 100;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.fin = true}, 100, 200));
    EXPECT_EQ(c.rcvNxt, 101u);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Send);
    EXPECT_TRUE(res.output.flags.ack);
}

TEST(TcpFsmTest, TimeWaitNonFinIgnored)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::TimeWait;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 1, 1));
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
}

TEST(TcpFsmTest, RxUnknownStateSendsRst)
{
    TcpConnection c = makeConnection();
    c.state = static_cast<TcpState>(200);
    c.sndNxt = 10;
    c.rcvNxt = 20;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 1, 1));
    EXPECT_EQ(res.output.type, TcpOutput::Type::SendReset);
}

TEST(TcpFsmTest, RetransmitInClosedReturnsNone)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Closed;
    auto out = TcpStateMachine::onRetransmitTimeout(c);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
}

TEST(TcpFsmTest, RetransmitSynSent)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onActiveOpen(c, 1000);
    auto out = TcpStateMachine::onRetransmitTimeout(c);
    EXPECT_EQ(out.type, TcpOutput::Type::Send);
    EXPECT_TRUE(out.flags.syn);
    EXPECT_EQ(out.seq, 1000u);
    EXPECT_EQ(c.retransmits, 1u);
}

TEST(TcpFsmTest, RetransmitSynReceived)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onPassiveOpen(c, ip("10.0.0.1"), 80, ip("10.0.0.2"), 5000, 500, 9000);
    auto out = TcpStateMachine::onRetransmitTimeout(c);
    EXPECT_EQ(out.type, TcpOutput::Type::Send);
    EXPECT_TRUE(out.flags.syn);
    EXPECT_TRUE(out.flags.ack);
    EXPECT_EQ(out.seq, 9000u);
    EXPECT_EQ(out.ack, 501u);
}

TEST(TcpFsmTest, DISABLED_RetransmitPendingData)
{
    TcpConnection c = makeConnection();
    c.mss = 1460;

    TcpStateMachine::onActiveOpen(c, 100);
    c.state = TcpState::Established;

    c.sndWnd = 65535;
    c.cwnd = 10;

    auto sendOut = TcpStateMachine::onAppSend(c, kPayload, 5);
    ASSERT_EQ(sendOut.type, TcpOutput::Type::Send);

    TcpStateMachine::onSegmentSent(c, sendOut);

    auto out = TcpStateMachine::onRetransmitTimeout(c);
    EXPECT_EQ(out.type, TcpOutput::Type::Send);
    EXPECT_TRUE(out.flags.ack);
    EXPECT_EQ(out.seq, c.sndUna);
    EXPECT_GT(out.payloadLen, 0u);
}

TEST(TcpFsmTest, RetransmitFin)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    c.mss = 1460;
    TcpStateMachine::onAppClose(c);
    c.finSent = true;
    auto out = TcpStateMachine::onRetransmitTimeout(c);
    EXPECT_EQ(out.type, TcpOutput::Type::Send);
    EXPECT_TRUE(out.flags.fin);
}

TEST(TcpFsmTest, RetransmitNoDataNoFin)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    c.finSent = false;
    auto out = TcpStateMachine::onRetransmitTimeout(c);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
}

TEST(TcpFsmTest, TimeWaitExpiredCloses)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::TimeWait;
    auto out = TcpStateMachine::onTimeWaitExpired(c);
    EXPECT_EQ(c.state, TcpState::Closed);
    EXPECT_TRUE(c.closed);
    EXPECT_EQ(out.type, TcpOutput::Type::Close);
}

TEST(TcpFsmTest, TimeWaitExpiredInOtherStateNoop)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    auto out = TcpStateMachine::onTimeWaitExpired(c);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
}

TEST(TcpFsmTest, OnSegmentSentIgnoresNonSend)
{
    TcpConnection c = makeConnection();
    c.sndNxt = 100;
    TcpOutput o = TcpOutput::none();
    TcpStateMachine::onSegmentSent(c, o);
    EXPECT_EQ(c.sndNxt, 100u);
}

TEST(TcpFsmTest, OnSegmentSentAdvancesSndNxtWithSyn)
{
    TcpConnection c = makeConnection();
    c.sndNxt = 100;
    TcpOutput o = TcpOutput::send({.syn = true}, 100, 0, 65535);
    TcpStateMachine::onSegmentSent(c, o);
    EXPECT_EQ(c.sndNxt, 101u);
    EXPECT_EQ(c.packetsSent, 1u);
}

TEST(TcpFsmTest, OnSegmentSentAdvancesSndNxtWithFin)
{
    TcpConnection c = makeConnection();
    c.sndNxt = 100;
    TcpOutput o = TcpOutput::send({.fin = true}, 100, 0, 65535);
    TcpStateMachine::onSegmentSent(c, o);
    EXPECT_EQ(c.sndNxt, 101u);
}

TEST(TcpFsmTest, OnSegmentSentAdvancesSndNxtWithPayload)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onActiveOpen(c, 100);
    c.state = TcpState::Established;
    c.sndWnd = 65535;
    c.cwnd = 10;
    c.sndNxt = 100;

    auto out = TcpStateMachine::onAppSend(c, kPayload, 5);
    ASSERT_EQ(out.type, TcpOutput::Type::Send);
    const uint32_t before = c.sndNxt;
    TcpStateMachine::onSegmentSent(c, out);
    EXPECT_EQ(c.sndNxt, before + 5u);
    EXPECT_EQ(c.bytesSent, 5u);
    EXPECT_EQ(c.packetsSent, 1u);
}

TEST(TcpFsmScenario, ActiveOpenHandshakeAndClose)
{
    TcpConnection c = makeConnection();
    c.sndWnd = 65535;
    c.cwnd = 10;

    auto syn = TcpStateMachine::onActiveOpen(c, 1000);
    ASSERT_TRUE(syn.flags.syn);
    TcpStateMachine::onSegmentSent(c, syn);
    EXPECT_EQ(c.sndNxt, 1001u);

    auto res = TcpStateMachine::onRxSegment(c, makeSeg({.syn = true, .ack = true}, 5000, 1001));
    EXPECT_EQ(c.state, TcpState::Established);
    TcpStateMachine::onSegmentSent(c, res.output);

    auto data = TcpStateMachine::onAppSend(c, kPayload, 5);
    ASSERT_EQ(data.type, TcpOutput::Type::Send);
    TcpStateMachine::onSegmentSent(c, data);

    TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 5001, c.sndNxt));
    EXPECT_EQ(c.state, TcpState::Established);

    auto fin = TcpStateMachine::onAppClose(c);
    EXPECT_EQ(c.state, TcpState::FinWait1);
    ASSERT_TRUE(fin.flags.fin);

    c.sndNxt += 1;
    TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 5001, c.sndNxt));
    EXPECT_EQ(c.state, TcpState::FinWait2);

    TcpStateMachine::onRxSegment(c, makeSeg({.fin = true}, 5001, c.sndNxt));
    EXPECT_EQ(c.state, TcpState::TimeWait);

    auto r3 = TcpStateMachine::onTimeWaitExpired(c);
    EXPECT_EQ(c.state, TcpState::Closed);
    EXPECT_EQ(r3.type, TcpOutput::Type::Close);
}

TEST(TcpFsmScenario, PassiveOpenHandshakeAndPeerClose)
{
    TcpConnection c = makeConnection();

    auto synack = TcpStateMachine::onPassiveOpen(c, ip("10.0.0.1"), 80, ip("10.0.0.2"), 5000, 500, 9000);
    ASSERT_TRUE(synack.flags.syn);
    ASSERT_TRUE(synack.flags.ack);
    TcpStateMachine::onSegmentSent(c, synack);

    TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 501, 9001));
    EXPECT_EQ(c.state, TcpState::Established);

    TcpFlags flags;
    flags.ack = true;
    flags.fin = true;

    TcpStateMachine::onRxSegment(c, makeSeg(flags, 501, 9001, 65535, kPayload, 5));
    EXPECT_EQ(c.state, TcpState::CloseWait);
    EXPECT_TRUE(c.finReceived);
    EXPECT_EQ(c.rcvNxt, 507u);

    auto fin = TcpStateMachine::onAppClose(c);
    EXPECT_EQ(c.state, TcpState::LastAck);
    ASSERT_TRUE(fin.flags.fin);

    c.sndNxt += 1;
    TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 507, c.sndNxt));
    EXPECT_EQ(c.state, TcpState::Closed);
    EXPECT_TRUE(c.closed);
}

TEST(TcpFsmTest, ProcessAckWindowUpdate)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onActiveOpen(c, 100);
    c.state = TcpState::Established;
    c.sndUna = 100;
    c.sndNxt = 200;
    c.rcvNxt = 500;
    c.sndWnd = 1000;
    c.sndWl1 = 150;
    c.sndWl2 = 150;

    TcpStateMachine::onRxSegment(c, makeSeg({.ack = true}, 500, 150, 2000));
    EXPECT_EQ(c.sndWnd, 2000u);
}