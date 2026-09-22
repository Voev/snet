// tests/tcp_fsm_test.cpp

#include <gtest/gtest.h>

#include <optional>
#include <vector>
#include <cstring>
#include <chrono>

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
    c.rxRing = new snet::RxRingBuffer();
    c.txRing = new snet::TxRingBuffer();
    return c;
}

void cleanupConnection(TcpConnection* c)
{
    if (c)
    {
        delete c->rxRing;
        delete c->txRing;
    }
}

TcpSegment makeSeg(TcpFlags f, uint32_t seq, uint32_t ack,
                   uint16_t win = 65535,
                   const uint8_t* data = nullptr,
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

TcpFlags flagsSyn()                     { TcpFlags f; f.setSyn(true); return f; }
TcpFlags flagsAck()                     { TcpFlags f; f.setAck(true); return f; }
TcpFlags flagsSynAck()                  { TcpFlags f; f.setSyn(true).setAck(true); return f; }
TcpFlags flagsFin()                     { TcpFlags f; f.setFin(true); return f; }
TcpFlags flagsFinAck()                  { TcpFlags f; f.setFin(true).setAck(true); return f; }
TcpFlags flagsRst()                     { TcpFlags f; f.setRst(true); return f; }
TcpFlags flagsRstAck()                  { TcpFlags f; f.setRst(true).setAck(true); return f; }

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
    EXPECT_TRUE(f.hasFin());
    EXPECT_TRUE(f.hasSyn());
    EXPECT_TRUE(f.hasRst());
    EXPECT_TRUE(f.hasPsh());
    EXPECT_TRUE(f.hasAck());
    EXPECT_TRUE(f.hasUrg());
}

TEST(TcpFlagsTest, FromByteNone)
{
    auto f = TcpFlags::fromByte(0x00);
    EXPECT_FALSE(f.hasFin());
    EXPECT_FALSE(f.hasSyn());
    EXPECT_FALSE(f.hasRst());
    EXPECT_FALSE(f.hasPsh());
    EXPECT_FALSE(f.hasAck());
    EXPECT_FALSE(f.hasUrg());
}

TEST(TcpFlagsTest, FromByteIndividualBits)
{
    EXPECT_TRUE(TcpFlags::fromByte(0x01).hasFin());
    EXPECT_TRUE(TcpFlags::fromByte(0x02).hasSyn());
    EXPECT_TRUE(TcpFlags::fromByte(0x04).hasRst());
    EXPECT_TRUE(TcpFlags::fromByte(0x08).hasPsh());
    EXPECT_TRUE(TcpFlags::fromByte(0x10).hasAck());
    EXPECT_TRUE(TcpFlags::fromByte(0x20).hasUrg());
}

TEST(TcpFlagsTest, ToByteRoundtrip)
{
    auto f = TcpFlags::fromByte(0x12);   // SYN | ACK
    EXPECT_EQ(f.toByte(), 0x12);
}

TEST(TcpFlagsTest, Setters)
{
    TcpFlags f;
    f.setSyn(true).setAck(true).setPsh(true);
    EXPECT_TRUE(f.hasSyn());
    EXPECT_TRUE(f.hasAck());
    EXPECT_TRUE(f.hasPsh());
    EXPECT_FALSE(f.hasFin());

    f.setSyn(false);
    EXPECT_FALSE(f.hasSyn());
    EXPECT_TRUE(f.hasAck());
}

TEST(TcpFlagsTest, Predicates)
{
    EXPECT_TRUE(flagsSyn().isSynOnly());
    EXPECT_FALSE(flagsSynAck().isSynOnly());
    EXPECT_TRUE(flagsSynAck().isSynAck());
    EXPECT_FALSE(flagsSyn().isSynAck());
    EXPECT_TRUE(flagsFin().isFinOrRst());
    EXPECT_TRUE(flagsRst().isFinOrRst());
    EXPECT_FALSE(flagsAck().isFinOrRst());
    EXPECT_TRUE(flagsFin().isFinRstNoData(0));
    EXPECT_FALSE(flagsFin().isFinRstNoData(5));
}

TEST(TcpFlagsTest, EqualityOperators)
{
    EXPECT_TRUE(flagsSynAck() == flagsSynAck());
    EXPECT_TRUE(flagsSyn() != flagsAck());
    EXPECT_TRUE(flagsRstAck() == TcpFlags::fromByte(0x14));
}

TEST(TcpOutputTest, None)
{
    auto none = TcpOutput::none();
    EXPECT_EQ(none.type, TcpOutput::Type::None);
}

TEST(TcpOutputTest, SendSyn)
{
    auto s = TcpOutput::sendSyn(1000, 65535);
    EXPECT_EQ(s.type, TcpOutput::Type::Send);
    EXPECT_TRUE(s.flags.hasSyn());
    EXPECT_FALSE(s.flags.hasAck());
    EXPECT_EQ(s.seq, 1000u);
    EXPECT_EQ(s.ack, 0u);
    EXPECT_EQ(s.window, 65535u);
    EXPECT_EQ(s.payloadLen, 0u);
}

TEST(TcpOutputTest, SendSynAck)
{
    auto s = TcpOutput::sendSynAck(1000, 2000, 65535);
    EXPECT_EQ(s.type, TcpOutput::Type::Send);
    EXPECT_TRUE(s.flags.hasSyn());
    EXPECT_TRUE(s.flags.hasAck());
    EXPECT_EQ(s.seq, 1000u);
    EXPECT_EQ(s.ack, 2000u);
}

TEST(TcpOutputTest, SendAck)
{
    auto s = TcpOutput::sendAck(1000, 2000, 65535);
    EXPECT_EQ(s.type, TcpOutput::Type::Send);
    EXPECT_FALSE(s.flags.hasSyn());
    EXPECT_TRUE(s.flags.hasAck());
    EXPECT_EQ(s.seq, 1000u);
    EXPECT_EQ(s.ack, 2000u);
}

TEST(TcpOutputTest, SendFinAck)
{
    auto s = TcpOutput::sendFinAck(1000, 2000, 65535);
    EXPECT_EQ(s.type, TcpOutput::Type::Send);
    EXPECT_TRUE(s.flags.hasFin());
    EXPECT_TRUE(s.flags.hasAck());
}

TEST(TcpOutputTest, SendData)
{
    auto s = TcpOutput::sendData(1000, 2000, 65535, kPayload, 5);
    EXPECT_EQ(s.type, TcpOutput::Type::Send);
    EXPECT_TRUE(s.flags.hasPsh());
    EXPECT_TRUE(s.flags.hasAck());
    EXPECT_EQ(s.seq, 1000u);
    EXPECT_EQ(s.ack, 2000u);
    EXPECT_EQ(s.payload, kPayload);
    EXPECT_EQ(s.payloadLen, 5u);
}

TEST(TcpOutputTest, SendRst)
{
    auto r = TcpOutput::sendRst(10, 20);
    EXPECT_EQ(r.type, TcpOutput::Type::SendReset);
    EXPECT_TRUE(r.flags.hasRst());
    EXPECT_TRUE(r.flags.hasAck());
    EXPECT_EQ(r.seq, 10u);
    EXPECT_EQ(r.ack, 20u);
}

TEST(TcpOutputTest, Close)
{
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
    cleanupConnection(&c);
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
    cleanupConnection(&c);
}

TEST(TcpFsmTest, ActiveOpenSendsSyn)
{
    TcpConnection c = makeConnection();
    auto out = TcpStateMachine::onActiveOpen(c, 1000);
    EXPECT_EQ(c.state, TcpState::SynSent);
    EXPECT_EQ(out.type, TcpOutput::Type::Send);
    EXPECT_TRUE(out.flags.hasSyn());
    EXPECT_FALSE(out.flags.hasAck());
    EXPECT_EQ(out.seq, 1000u);
    EXPECT_EQ(c.iss, 1000u);
    EXPECT_EQ(c.sndUna, 1000u);
    EXPECT_EQ(c.sndNxt, 1000u);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, ActiveOpenIgnoredIfNotClosed)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    auto out = TcpStateMachine::onActiveOpen(c, 1000);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, PassiveOpenSendsSynAck)
{
    TcpConnection c = makeConnection();
    auto out = TcpStateMachine::onPassiveOpen(
        c, ip("10.0.0.1"), 80, ip("10.0.0.2"), 5000, 500, 9000);
    EXPECT_EQ(c.state, TcpState::SynReceived);
    EXPECT_TRUE(c.passiveOpen);
    EXPECT_EQ(c.irs, 500u);
    EXPECT_EQ(c.rcvNxt, 501u);
    EXPECT_EQ(c.iss, 9000u);
    EXPECT_EQ(out.type, TcpOutput::Type::Send);
    EXPECT_TRUE(out.flags.hasSyn());
    EXPECT_TRUE(out.flags.hasAck());
    EXPECT_EQ(out.seq, 9000u);
    EXPECT_EQ(out.ack, 501u);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, PassiveOpenIgnoredIfNotClosed)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    auto out = TcpStateMachine::onPassiveOpen(
        c, ip("10.0.0.1"), 80, ip("10.0.0.2"), 5000, 1, 2);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
    cleanupConnection(&c);
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
    EXPECT_TRUE(out.flags.hasPsh());
    EXPECT_TRUE(out.flags.hasAck());
    EXPECT_EQ(out.payloadLen, 5u);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, AppSendNotEstablished)
{
    TcpConnection c = makeConnection();
    auto out = TcpStateMachine::onAppSend(c, kPayload, 5);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, AppSendZeroLength)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    auto out = TcpStateMachine::onAppSend(c, nullptr, 0);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, AppSendZeroWindow)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    c.sndWnd = 0;
    c.cwnd = 0;
    auto out = TcpStateMachine::onAppSend(c, kPayload, 5);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, AppCloseFromEstablished)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    auto out = TcpStateMachine::onAppClose(c);
    EXPECT_EQ(c.state, TcpState::FinWait1);
    EXPECT_TRUE(c.finSent);
    EXPECT_EQ(out.type, TcpOutput::Type::Send);
    EXPECT_TRUE(out.flags.hasFin());
    EXPECT_TRUE(out.flags.hasAck());
    cleanupConnection(&c);
}

TEST(TcpFsmTest, AppCloseFromCloseWait)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::CloseWait;
    auto out = TcpStateMachine::onAppClose(c);
    EXPECT_EQ(c.state, TcpState::LastAck);
    EXPECT_TRUE(c.finSent);
    EXPECT_EQ(out.type, TcpOutput::Type::Send);
    EXPECT_TRUE(out.flags.hasFin());
    cleanupConnection(&c);
}

TEST(TcpFsmTest, AppCloseIgnoredInOtherStates)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::SynSent;
    auto out = TcpStateMachine::onAppClose(c);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
    cleanupConnection(&c);
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
    EXPECT_TRUE(out.flags.hasRst());
    EXPECT_TRUE(out.flags.hasAck());
    EXPECT_EQ(out.seq, 100u);
    EXPECT_EQ(out.ack, 200u);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, RxRstClosesConnection)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg(flagsRst(), 0, 0));
    EXPECT_EQ(c.state, TcpState::Closed);
    EXPECT_TRUE(c.closed);
    EXPECT_TRUE(res.closed);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Close);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, RxInClosedWithAckSendsRst)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Closed;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg(flagsAck(), 100, 200));
    EXPECT_EQ(res.output.type, TcpOutput::Type::SendReset);
    EXPECT_EQ(res.output.seq, 200u);
    EXPECT_EQ(res.output.ack, 0u);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, RxInClosedWithoutAckSendsRst)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Closed;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsSyn(), 100, 0, 65535, kPayload, 5));
    EXPECT_EQ(res.output.type, TcpOutput::Type::SendReset);
    EXPECT_EQ(res.output.seq, 0u);
    EXPECT_EQ(res.output.ack, 106u);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, SynSentReceivesSynAck)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onActiveOpen(c, 1000);
    c.sndNxt = 1001;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsSynAck(), 5000, 1001));
    EXPECT_EQ(c.state, TcpState::Established);
    EXPECT_TRUE(res.connectionEstablished);
    EXPECT_EQ(c.irs, 5000u);
    EXPECT_EQ(c.rcvNxt, 5001u);
    EXPECT_EQ(c.sndUna, 1001u);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Send);
    EXPECT_TRUE(res.output.flags.hasAck());
    cleanupConnection(&c);
}

TEST(TcpFsmTest, SynSentReceivesSynAckBadAck)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onActiveOpen(c, 1000);
    c.sndNxt = 1001;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsSynAck(), 5000, 9999));
    EXPECT_EQ(res.output.type, TcpOutput::Type::SendReset);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, SynSentReceivesSynOnly)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onActiveOpen(c, 1000);
    c.sndNxt = 1001;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsSyn(), 5000, 0));
    EXPECT_EQ(c.state, TcpState::SynReceived);
    EXPECT_EQ(c.irs, 5000u);
    EXPECT_EQ(c.rcvNxt, 5001u);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Send);
    EXPECT_TRUE(res.output.flags.hasSyn());
    EXPECT_TRUE(res.output.flags.hasAck());
    cleanupConnection(&c);
}

TEST(TcpFsmTest, SynSentIgnoresOtherSegments)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onActiveOpen(c, 1000);
    auto res = TcpStateMachine::onRxSegment(c, makeSeg(flagsAck(), 1, 1));
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
    EXPECT_EQ(c.state, TcpState::SynSent);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, SynReceivedAcceptsAck)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onPassiveOpen(
        c, ip("10.0.0.1"), 80, ip("10.0.0.2"), 5000, 500, 9000);
    c.sndNxt = 9001;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsAck(), 501, 9001));
    EXPECT_EQ(c.state, TcpState::Established);
    EXPECT_TRUE(res.connectionEstablished);
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, SynReceivedAcceptsAckWithData)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onPassiveOpen(
        c, ip("10.0.0.1"), 80, ip("10.0.0.2"), 5000, 500, 9000);
    c.sndNxt = 9001;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsAck(), 501, 9001, 65535, kPayload, 5));
    EXPECT_EQ(c.state, TcpState::Established);
    EXPECT_TRUE(res.deliverToApp);
    EXPECT_EQ(c.rcvNxt, 506u);
    EXPECT_EQ(c.bytesReceived, 5u);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, SynReceivedRetransmittedSyn)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onPassiveOpen(
        c, ip("10.0.0.1"), 80, ip("10.0.0.2"), 5000, 500, 9000);
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsSyn(), 500, 0));
    EXPECT_EQ(res.output.type, TcpOutput::Type::Send);
    EXPECT_TRUE(res.output.flags.hasSyn());
    EXPECT_TRUE(res.output.flags.hasAck());
    EXPECT_EQ(res.output.seq, 9000u);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, SynReceivedUnexpectedSegmentSendsRst)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onPassiveOpen(
        c, ip("10.0.0.1"), 80, ip("10.0.0.2"), 5000, 500, 9000);
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsAck(), 9999, 9999));
    EXPECT_EQ(res.output.type, TcpOutput::Type::SendReset);
    cleanupConnection(&c);
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
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsAck(), 100, 200, 65535, kPayload, 5));
    EXPECT_TRUE(res.deliverToApp);
    EXPECT_EQ(c.rcvNxt, 105u);
    EXPECT_EQ(c.bytesReceived, 5u);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Send);
    EXPECT_TRUE(res.output.flags.hasAck());
    cleanupConnection(&c);
}

TEST(TcpFsmTest, EstablishedProcessesOutOfOrderData)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    c.rcvNxt = 100;
    c.sndNxt = 200;
    c.sndUna = 200;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsAck(), 200, 200, 65535, kPayload, 5));
    EXPECT_FALSE(res.deliverToApp);
    EXPECT_EQ(c.dupAcks, 1u);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, EstablishedProcessesRetransmit)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    c.rcvNxt = 200;
    c.sndNxt = 300;
    c.sndUna = 300;
    TcpStateMachine::onRxSegment(
        c, makeSeg(flagsAck(), 197, 300, 65535, kPayload, 5));
    EXPECT_EQ(c.rcvNxt, 200u);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, EstablishedFinClosesToCloseWait)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    c.rcvNxt = 100;
    c.sndNxt = 200;
    c.sndUna = 200;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsFinAck(), 100, 200));
    EXPECT_EQ(c.state, TcpState::CloseWait);
    EXPECT_TRUE(c.finReceived);
    EXPECT_EQ(c.rcvNxt, 101u);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Send);
    EXPECT_TRUE(res.output.flags.hasAck());
    cleanupConnection(&c);
}

TEST(TcpFsmTest, EstablishedAckOnlyNoPendingData)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    c.rcvNxt = 100;
    c.sndNxt = 200;
    c.sndUna = 200;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsAck(), 100, 200));
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
    cleanupConnection(&c);
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
    TcpStateMachine::onRxSegment(
        c, makeSeg(flagsAck(), 500, 150, 1000));
    EXPECT_EQ(c.sndUna, 150u);
    EXPECT_EQ(c.sndWnd, 1000u);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, FinWait1AckTransitionsToFinWait2)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::FinWait1;
    c.sndNxt = 200;
    c.sndUna = 200;
    c.rcvNxt = 100;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsAck(), 100, 200));
    EXPECT_EQ(c.state, TcpState::FinWait2);
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, FinWait1AckWithFinTransitionsToClosing)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::FinWait1;
    c.sndNxt = 200;
    c.sndUna = 200;
    c.rcvNxt = 100;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsFinAck(), 100, 200));
    EXPECT_EQ(c.state, TcpState::Closing);
    EXPECT_TRUE(c.finReceived);
    EXPECT_EQ(c.rcvNxt, 101u);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Send);
    EXPECT_TRUE(res.output.flags.hasAck());
    cleanupConnection(&c);
}

TEST(TcpFsmTest, FinWait1FinOnlySimultaneousClose)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::FinWait1;
    c.sndNxt = 200;
    c.sndUna = 200;
    c.rcvNxt = 100;
    TcpStateMachine::onRxSegment(c, makeSeg(flagsFin(), 100, 0));
    EXPECT_EQ(c.state, TcpState::Closing);
    EXPECT_TRUE(c.finReceived);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, FinWait1DataDelivery)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::FinWait1;
    c.sndNxt = 200;
    c.sndUna = 200;
    c.rcvNxt = 100;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsAck(), 100, 200, 65535, kPayload, 5));
    EXPECT_TRUE(res.deliverToApp);
    EXPECT_EQ(c.rcvNxt, 105u);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, FinWait2FinTransitionsToTimeWait)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::FinWait2;
    c.rcvNxt = 100;
    c.sndNxt = 200;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsFin(), 100, 200));
    EXPECT_EQ(c.state, TcpState::TimeWait);
    EXPECT_TRUE(c.finReceived);
    EXPECT_EQ(c.rcvNxt, 101u);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Send);
    EXPECT_TRUE(res.output.flags.hasAck());
    cleanupConnection(&c);
}

TEST(TcpFsmTest, FinWait2DataDelivery)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::FinWait2;
    c.rcvNxt = 100;
    c.sndNxt = 200;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsAck(), 100, 200, 65535, kPayload, 5));
    EXPECT_TRUE(res.deliverToApp);
    EXPECT_EQ(c.rcvNxt, 105u);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, FinWait2NoDataNoFin)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::FinWait2;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg(flagsAck(), 1, 1));
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, CloseWaitIgnoresSegment)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::CloseWait;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg(flagsAck(), 1, 1));
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
    EXPECT_EQ(c.state, TcpState::CloseWait);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, ClosingAckTransitionsToTimeWait)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Closing;
    c.sndNxt = 200;
    c.sndUna = 200;
    TcpStateMachine::onRxSegment(c, makeSeg(flagsAck(), 1, 200));
    EXPECT_EQ(c.state, TcpState::TimeWait);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, ClosingNonMatchingAckIgnored)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Closing;
    c.sndNxt = 200;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsAck(), 1, 999));
    EXPECT_EQ(c.state, TcpState::Closing);
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, LastAckAckClosesConnection)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::LastAck;
    c.sndNxt = 200;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsAck(), 1, 200));
    EXPECT_EQ(c.state, TcpState::Closed);
    EXPECT_TRUE(c.closed);
    EXPECT_TRUE(res.closed);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Close);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, LastAckNonMatchingAckIgnored)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::LastAck;
    c.sndNxt = 200;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsAck(), 1, 999));
    EXPECT_EQ(c.state, TcpState::LastAck);
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, TimeWaitFinResendsAck)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::TimeWait;
    c.sndNxt = 200;
    c.rcvNxt = 100;
    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsFin(), 100, 200));
    EXPECT_EQ(c.rcvNxt, 101u);
    EXPECT_EQ(res.output.type, TcpOutput::Type::Send);
    EXPECT_TRUE(res.output.flags.hasAck());
    cleanupConnection(&c);
}

TEST(TcpFsmTest, TimeWaitNonFinIgnored)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::TimeWait;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg(flagsAck(), 1, 1));
    EXPECT_EQ(res.output.type, TcpOutput::Type::None);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, RxUnknownStateSendsRst)
{
    TcpConnection c = makeConnection();
    c.state = static_cast<TcpState>(200);
    c.sndNxt = 10;
    c.rcvNxt = 20;
    auto res = TcpStateMachine::onRxSegment(c, makeSeg(flagsAck(), 1, 1));
    EXPECT_EQ(res.output.type, TcpOutput::Type::SendReset);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, RetransmitInClosedReturnsNone)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Closed;
    auto out = TcpStateMachine::onRetransmitTimeout(c);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, RetransmitSynSent)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onActiveOpen(c, 1000);
    auto out = TcpStateMachine::onRetransmitTimeout(c);
    EXPECT_EQ(out.type, TcpOutput::Type::Send);
    EXPECT_TRUE(out.flags.hasSyn());
    EXPECT_EQ(out.seq, 1000u);
    EXPECT_EQ(c.retransmits, 1u);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, RetransmitSynReceived)
{
    TcpConnection c = makeConnection();
    TcpStateMachine::onPassiveOpen(
        c, ip("10.0.0.1"), 80, ip("10.0.0.2"), 5000, 500, 9000);
    auto out = TcpStateMachine::onRetransmitTimeout(c);
    EXPECT_EQ(out.type, TcpOutput::Type::Send);
    EXPECT_TRUE(out.flags.hasSyn());
    EXPECT_TRUE(out.flags.hasAck());
    EXPECT_EQ(out.seq, 9000u);
    EXPECT_EQ(out.ack, 501u);
    cleanupConnection(&c);
}

// NOTE: disabled — requires TxRingBuffer::peekAt + onSegmentSent fix
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
    EXPECT_TRUE(out.flags.hasAck());
    EXPECT_EQ(out.seq, c.sndUna);
    EXPECT_GT(out.payloadLen, 0u);
    cleanupConnection(&c);
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
    EXPECT_TRUE(out.flags.hasFin());
    cleanupConnection(&c);
}

TEST(TcpFsmTest, RetransmitNoDataNoFin)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    c.finSent = false;
    auto out = TcpStateMachine::onRetransmitTimeout(c);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, TimeWaitExpiredCloses)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::TimeWait;
    auto out = TcpStateMachine::onTimeWaitExpired(c);
    EXPECT_EQ(c.state, TcpState::Closed);
    EXPECT_TRUE(c.closed);
    EXPECT_EQ(out.type, TcpOutput::Type::Close);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, TimeWaitExpiredInOtherStateNoop)
{
    TcpConnection c = makeConnection();
    c.state = TcpState::Established;
    auto out = TcpStateMachine::onTimeWaitExpired(c);
    EXPECT_EQ(out.type, TcpOutput::Type::None);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, OnSegmentSentIgnoresNonSend)
{
    TcpConnection c = makeConnection();
    c.sndNxt = 100;
    TcpOutput o = TcpOutput::none();
    TcpStateMachine::onSegmentSent(c, o);
    EXPECT_EQ(c.sndNxt, 100u);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, OnSegmentSentAdvancesSndNxtWithSyn)
{
    TcpConnection c = makeConnection();
    c.sndNxt = 100;
    TcpOutput o = TcpOutput::sendSyn(100, 65535);
    TcpStateMachine::onSegmentSent(c, o);
    EXPECT_EQ(c.sndNxt, 101u);
    EXPECT_EQ(c.packetsSent, 1u);
    cleanupConnection(&c);
}

TEST(TcpFsmTest, OnSegmentSentAdvancesSndNxtWithFin)
{
    TcpConnection c = makeConnection();
    c.sndNxt = 100;
    TcpOutput o = TcpOutput::sendFinAck(100, 0, 65535);
    TcpStateMachine::onSegmentSent(c, o);
    EXPECT_EQ(c.sndNxt, 101u);
    cleanupConnection(&c);
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
    cleanupConnection(&c);
}

TEST(TcpFsmScenario, ActiveOpenHandshakeAndClose)
{
    TcpConnection c = makeConnection();
    c.sndWnd = 65535;
    c.cwnd = 10;

    auto syn = TcpStateMachine::onActiveOpen(c, 1000);
    ASSERT_TRUE(syn.flags.hasSyn());
    TcpStateMachine::onSegmentSent(c, syn);
    EXPECT_EQ(c.sndNxt, 1001u);

    auto res = TcpStateMachine::onRxSegment(
        c, makeSeg(flagsSynAck(), 5000, 1001));
    EXPECT_EQ(c.state, TcpState::Established);
    TcpStateMachine::onSegmentSent(c, res.output);

    auto data = TcpStateMachine::onAppSend(c, kPayload, 5);
    ASSERT_EQ(data.type, TcpOutput::Type::Send);
    TcpStateMachine::onSegmentSent(c, data);

    TcpStateMachine::onRxSegment(c, makeSeg(flagsAck(), 5001, c.sndNxt));
    EXPECT_EQ(c.state, TcpState::Established);

    auto fin = TcpStateMachine::onAppClose(c);
    EXPECT_EQ(c.state, TcpState::FinWait1);
    ASSERT_TRUE(fin.flags.hasFin());

    c.sndNxt += 1;
    TcpStateMachine::onRxSegment(c, makeSeg(flagsAck(), 5001, c.sndNxt));
    EXPECT_EQ(c.state, TcpState::FinWait2);

    TcpStateMachine::onRxSegment(c, makeSeg(flagsFin(), 5001, c.sndNxt));
    EXPECT_EQ(c.state, TcpState::TimeWait);

    auto r3 = TcpStateMachine::onTimeWaitExpired(c);
    EXPECT_EQ(c.state, TcpState::Closed);
    EXPECT_EQ(r3.type, TcpOutput::Type::Close);
    cleanupConnection(&c);
}

TEST(TcpFsmScenario, PassiveOpenHandshakeAndPeerClose)
{
    TcpConnection c = makeConnection();

    auto synack = TcpStateMachine::onPassiveOpen(
        c, ip("10.0.0.1"), 80, ip("10.0.0.2"), 5000, 500, 9000);
    ASSERT_TRUE(synack.flags.hasSyn());
    ASSERT_TRUE(synack.flags.hasAck());
    TcpStateMachine::onSegmentSent(c, synack);

    TcpStateMachine::onRxSegment(c, makeSeg(flagsAck(), 501, 9001));
    EXPECT_EQ(c.state, TcpState::Established);

    // Peer sends FIN + data
    TcpStateMachine::onRxSegment(
        c, makeSeg(flagsFinAck(), 501, 9001, 65535, kPayload, 5));
    EXPECT_EQ(c.state, TcpState::CloseWait);
    EXPECT_TRUE(c.finReceived);
    EXPECT_EQ(c.rcvNxt, 507u);

    auto fin = TcpStateMachine::onAppClose(c);
    EXPECT_EQ(c.state, TcpState::LastAck);
    ASSERT_TRUE(fin.flags.hasFin());

    c.sndNxt += 1;
    TcpStateMachine::onRxSegment(c, makeSeg(flagsAck(), 507, c.sndNxt));
    EXPECT_EQ(c.state, TcpState::Closed);
    EXPECT_TRUE(c.closed);
    cleanupConnection(&c);
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

    TcpStateMachine::onRxSegment(
        c, makeSeg(flagsAck(), 500, 150, 2000));
    EXPECT_EQ(c.sndWnd, 2000u);
    cleanupConnection(&c);
}