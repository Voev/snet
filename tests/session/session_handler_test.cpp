#include <gtest/gtest.h>
#include <cstdint>
#include <memory>
#include <string>

#include <snet/session/session_handler.hpp>

using namespace snet;
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

    bool createContext(Session*) override
    {
        return true;
    }

    bool destroyContext(Session*) override
    {
        return true;
    }

    PacketStatus processPacket(Session*, layers::Packet*, PacketStatus status) override
    {
        return status;
    }

    using Base::passToNext;
    using Base::getContext;
    using Base::setContext;
    using Base::allocateContext;
    using Base::removeContext;
    using Base::deallocateContext;
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

    bool createContext(Session*) override
    {
        return true;
    }

    bool destroyContext(Session*) override
    {
        return true;
    }

    PacketStatus processPacket(Session* s, layers::Packet* p, PacketStatus status) override
    {
        ++processCalls;
        lastSession = s;
        lastPacket = p;
        lastStatus = status;
        return PacketHandled;
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

TEST(ISessionHandlerTest, SetContextWithoutManagerReturnsFalse)
{
    TestHandler h;
    FakeSession session;
    TestCtx ctx;
    EXPECT_FALSE(h.setContext<TestCtx>(&session, &ctx));
}

TEST(ISessionHandlerTest, SetContextWithNullSessionReturnsFalse)
{
    TestHandler h;
    FakeSessionManager mgr;
    h.setSessionManager(&mgr);
    TestCtx ctx;
    EXPECT_FALSE(h.setContext<TestCtx>(nullptr, &ctx));
}

TEST(ISessionHandlerTest, SetContextForwardsToManager)
{
    TestHandler h;
    FakeSessionManager mgr;
    FakeSession session;
    TestCtx ctx;
    h.setSessionManager(&mgr);

    EXPECT_TRUE(h.setContext<TestCtx>(&session, &ctx, 2));
    EXPECT_EQ(mgr.setContextCalls, 1);
    EXPECT_EQ(mgr.lastSetSession, &session);
    EXPECT_EQ(mgr.lastSetCtx, &ctx);
    EXPECT_EQ(mgr.lastSetIndex, 2u);
}

TEST(ISessionHandlerTest, AllocateContextWithoutManagerReturnsNull)
{
    TestHandler h;
    EXPECT_EQ(h.allocateContext<TestCtx>(), nullptr);
}

TEST(ISessionHandlerTest, AllocateContextForwardsToManager)
{
    TestHandler h;
    FakeSessionManager mgr;
    h.setSessionManager(&mgr);

    h.allocateContext<TestCtx>();
    EXPECT_EQ(mgr.allocateContextCalls, 1);
}

TEST(ISessionHandlerTest, AllocateContextWithArgsWithoutManagerReturnsNull)
{
    TestHandler h;
    EXPECT_EQ(h.allocateContext<TestCtx>(42), nullptr);
}

TEST(ISessionHandlerTest, AllocateContextWithArgsForwardsToManager)
{
    TestHandler h;
    FakeSessionManager mgr;
    h.setSessionManager(&mgr);

    h.allocateContext<TestCtx>(42, 3.14);
    EXPECT_EQ(mgr.allocateContextArgsCalls, 1);
}

TEST(ISessionHandlerTest, RemoveContextWithoutManagerReturnsNull)
{
    TestHandler h;
    FakeSession session;
    EXPECT_EQ(h.removeContext<TestCtx>(&session), nullptr);
}

TEST(ISessionHandlerTest, RemoveContextForwardsToManager)
{
    TestHandler h;
    FakeSessionManager mgr;
    FakeSession session;
    h.setSessionManager(&mgr);

    h.removeContext<TestCtx>(&session, 1);
    EXPECT_EQ(mgr.removeContextCalls, 1);
    EXPECT_EQ(mgr.lastRemoveSession, &session);
    EXPECT_EQ(mgr.lastRemoveIndex, 1u);
}

TEST(ISessionHandlerTest, DeallocateContextWithoutManagerDoesNothing)
{
    TestHandler h;
    TestCtx ctx;
    h.deallocateContext<TestCtx>(&ctx);
    EXPECT_EQ(0, 0);
}

TEST(ISessionHandlerTest, DeallocateContextForwardsToManager)
{
    TestHandler h;
    FakeSessionManager mgr;
    h.setSessionManager(&mgr);
    TestCtx ctx;

    h.deallocateContext<TestCtx>(&ctx);
    EXPECT_EQ(mgr.deallocateContextCalls, 1);
    EXPECT_EQ(mgr.lastDeallocate, &ctx);
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

TEST(ISessionHandlerTest, SetContextDefaultIndexIsZero)
{
    TestHandler h;
    FakeSessionManager mgr;
    FakeSession session;
    TestCtx ctx;
    h.setSessionManager(&mgr);

    h.setContext<TestCtx>(&session, &ctx);
    EXPECT_EQ(mgr.lastSetIndex, 0u);
}

TEST(ISessionHandlerTest, RemoveContextDefaultIndexIsZero)
{
    TestHandler h;
    FakeSessionManager mgr;
    FakeSession session;
    h.setSessionManager(&mgr);

    h.removeContext<TestCtx>(&session);
    EXPECT_EQ(mgr.lastRemoveIndex, 0u);
}