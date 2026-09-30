#include <gtest/gtest.h>
#include <cstdint>
#include <memory>
#include <string>

#include <snet/session/session_handler.hpp>

using namespace snet;
using namespace snet::layers;
using namespace snet::session;

namespace
{

struct FakeSession
{
    int id{0};
};

struct FakePacket
{
    int data{0};
};

struct FakeSessionManager
{
    using Session = FakeSession;
    using Key = uint32_t;

    FakeSession session;
    FakePacket packet;

    int getContextCalls{0};
    int setContextCalls{0};
    int allocateContextCalls{0};
    int allocateContextArgsCalls{0};
    int removeContextCalls{0};
    int deallocateContextCalls{0};

    FakeSession* lastGetSession{nullptr};
    size_t lastGetIndex{0};
    FakeSession* lastSetSession{nullptr};
    void* lastSetCtx{nullptr};
    size_t lastSetIndex{0};
    FakeSession* lastRemoveSession{nullptr};
    size_t lastRemoveIndex{0};
    void* lastDeallocate{nullptr};

    template <typename ContextType>
    ContextType* getContext(Session* s, size_t index = 0)
    {
        ++getContextCalls;
        lastGetSession = s;
        lastGetIndex = index;
        return nullptr;
    }

    template <typename ContextType>
    bool setContext(Session* s, ContextType* ctx, size_t index = 0)
    {
        ++setContextCalls;
        lastSetSession = s;
        lastSetCtx = ctx;
        lastSetIndex = index;
        return true;
    }

    template <typename ContextType>
    ContextType* allocateContext()
    {
        ++allocateContextCalls;
        return nullptr;
    }

    template <typename ContextType, typename... Args>
    ContextType* allocateContext(Args&&...)
    {
        ++allocateContextArgsCalls;
        return nullptr;
    }

    template <typename ContextType>
    ContextType* removeContext(Session* s, size_t index = 0)
    {
        ++removeContextCalls;
        lastRemoveSession = s;
        lastRemoveIndex = index;
        return nullptr;
    }

    template <typename ContextType>
    void deallocateContext(ContextType* ctx)
    {
        ++deallocateContextCalls;
        lastDeallocate = ctx;
    }
};

struct TestCtx
{
    int value{0};
};

class TestHandler : public ISessionHandler<FakeSessionManager>
{
public:
    using Base = ISessionHandler<FakeSessionManager>;

    const char* name() const override
    {
        return "TestHandler";
    }

    layers::PacketStatus processPacket(Session*, layers::Packet*, layers::PacketStatus status) override
    {
        return status;
    }

    using Base::passToNext;
    using Base::getContext;
    using Base::getSessionManager;
};

struct CountingHandler : public ISessionHandler<FakeSessionManager>
{
    int processCalls{0};
    PacketStatus lastStatus{UnknownStatus};
    Session* lastSession{nullptr};
    layers::Packet* lastPacket{nullptr};

    const char* name() const override
    {
        return "CountingHandler";
    }

    layers::PacketStatus processPacket(Session* s, layers::Packet* p, layers::PacketStatus status) override
    {
        ++processCalls;
        lastSession = s;
        lastPacket = p;
        lastStatus = status;
        return layers::PacketHandled;
    }
};

} // namespace

TEST(ISessionHandlerTest, NameIsVirtual)
{
    TestHandler h;
    EXPECT_STREQ(h.name(), "TestHandler");
}

TEST(ISessionHandlerTest, DefaultSessionManagerIsNull)
{
    TestHandler h;
    EXPECT_EQ(h.getSessionManager(), nullptr);
}

TEST(ISessionHandlerTest, SetSessionManager)
{
    TestHandler h;
    FakeSessionManager mgr;
    h.setSessionManager(&mgr);
    EXPECT_EQ(h.getSessionManager(), &mgr);
}

TEST(ISessionHandlerTest, GetContextWithoutManagerReturnsNull)
{
    TestHandler h;
    FakeSession session;
    EXPECT_EQ(h.getContext<TestCtx>(&session), nullptr);
}

TEST(ISessionHandlerTest, GetContextWithNullSessionReturnsNull)
{
    TestHandler h;
    FakeSessionManager mgr;
    h.setSessionManager(&mgr);
    EXPECT_EQ(h.getContext<TestCtx>(nullptr), nullptr);
}

TEST(ISessionHandlerTest, GetContextForwardsToManager)
{
    TestHandler h;
    FakeSessionManager mgr;
    FakeSession session;
    h.setSessionManager(&mgr);

    h.getContext<TestCtx>(&session, 3);

    EXPECT_EQ(mgr.getContextCalls, 1);
    EXPECT_EQ(mgr.lastGetSession, &session);
    EXPECT_EQ(mgr.lastGetIndex, 3u);
}

TEST(ISessionHandlerTest, GetContextDefaultIndexIsZero)
{
    TestHandler h;
    FakeSessionManager mgr;
    FakeSession session;
    h.setSessionManager(&mgr);

    h.getContext<TestCtx>(&session);
    EXPECT_EQ(mgr.lastGetIndex, 0u);
}

