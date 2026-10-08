#include <gtest/gtest.h>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <snet/session/session_pipeline.hpp>

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

    int setSessionManagerCalls{0};
    void* lastSessionManagerArg{nullptr};

    template <typename ContextType>
    ContextType* getContext(Session*, size_t = 0)
    {
        return nullptr;
    }

    template <typename ContextType>
    bool setContext(Session*, ContextType*, size_t = 0)
    {
        return true;
    }

    template <typename ContextType>
    ContextType* allocateContext()
    {
        return nullptr;
    }

    template <typename ContextType, typename... Args>
    ContextType* allocateContext(Args&&...)
    {
        return nullptr;
    }

    template <typename ContextType>
    ContextType* removeContext(Session*, size_t = 0)
    {
        return nullptr;
    }

    template <typename ContextType>
    void deallocateContext(ContextType*)
    {
    }
};

using Pipeline = SessionPipeline<FakeSessionManager>;
using Handler = ISessionHandler<FakeSessionManager>;
using Packet = snet::layers::Packet;

struct NamedHandler : public ISessionHandler<FakeSessionManager>
{
    std::string handlerName;
    int createCalls{0};
    int destroyCalls{0};
    int processCalls{0};
    bool createResult{true};
    bool destroyResult{true};
    PacketStatus processResult{snet::layers::PacketStatus::TcpMessageHandled};
    PacketStatus lastProcessStatus{snet::layers::PacketStatus::Error_NoContext};
    Session* lastSession{nullptr};
    Packet* lastPacket{nullptr};

    explicit NamedHandler(std::string n)
        : handlerName(std::move(n))
    {
    }

    const char* name() const override
    {
        return handlerName.c_str();
    }

    PacketStatus processPacket(Session* s, Packet* p, PacketStatus status) override
    {
        ++processCalls;
        lastSession = s;
        lastPacket = p;
        lastProcessStatus = status;
        return processResult;
    }
};

struct AnotherHandler : public ISessionHandler<FakeSessionManager>
{
    const char* name() const override
    {
        return "AnotherHandler";
    }
    PacketStatus processPacket(Session*, Packet*, PacketStatus) override
    {
        return PacketStatus::pass();
    }
};

std::shared_ptr<NamedHandler> makeHandler(const std::string& name)
{
    return std::make_shared<NamedHandler>(name);
}

} // namespace

TEST(SessionPipelineTest, DefaultConstructedIsEmpty)
{
    Pipeline p;
    EXPECT_TRUE(p.empty());
    EXPECT_EQ(p.size(), 0u);
    EXPECT_EQ(p.getFirst(), nullptr);
    EXPECT_EQ(p.getLast(), nullptr);
}

TEST(SessionPipelineTest, ConstructorWithManager)
{
    FakeSessionManager mgr;
    Pipeline p(&mgr);
    EXPECT_TRUE(p.empty());
}

TEST(SessionPipelineTest, AddSingleHandler)
{
    Pipeline p;
    auto h = makeHandler("A");
    p.add(h);

    EXPECT_FALSE(p.empty());
    EXPECT_EQ(p.size(), 1u);
    EXPECT_EQ(p.getFirst(), h);
    EXPECT_EQ(p.getLast(), h);
}

TEST(SessionPipelineTest, AddMultipleHandlers)
{
    Pipeline p;
    auto a = makeHandler("A");
    auto b = makeHandler("B");
    auto c = makeHandler("C");

    p.add(a).add(b).add(c);

    EXPECT_EQ(p.size(), 3u);
    EXPECT_EQ(p.getFirst(), a);
    EXPECT_EQ(p.getLast(), c);
}

TEST(SessionPipelineTest, AddNullptrIsIgnored)
{
    Pipeline p;
    auto a = makeHandler("A");

    p.add(nullptr);
    EXPECT_TRUE(p.empty());

    p.add(a);
    p.add(nullptr);
    EXPECT_EQ(p.size(), 1u);
    EXPECT_EQ(p.getFirst(), a);
}

TEST(SessionPipelineTest, AddHandlerTemplate)
{
    Pipeline p;
    p.addHandler<NamedHandler>("X");

    EXPECT_EQ(p.size(), 1u);
    ASSERT_NE(p.getFirst(), nullptr);
    EXPECT_STREQ(p.getFirst()->name(), "X");
}

TEST(SessionPipelineTest, AddHandlerTemplateMultiple)
{
    Pipeline p;
    p.addHandler<NamedHandler>("A").addHandler<NamedHandler>("B").addHandler<AnotherHandler>();

    EXPECT_EQ(p.size(), 3u);
    EXPECT_STREQ(p.getFirst()->name(), "A");
    EXPECT_STREQ(p.getLast()->name(), "AnotherHandler");
}

TEST(SessionPipelineTest, SetSessionManagerPropagates)
{
    FakeSessionManager mgr;
    Pipeline p;

    auto a = makeHandler("A");
    auto b = makeHandler("B");
    p.add(a).add(b);

    p.setSessionManager(&mgr);

    EXPECT_EQ(a->getSessionManager(), &mgr);
    EXPECT_EQ(b->getSessionManager(), &mgr);
}

TEST(SessionPipelineTest, ConstructorManagerPropagatesToAddedHandlers)
{
    FakeSessionManager mgr;
    Pipeline p(&mgr);

    auto a = makeHandler("A");
    p.add(a);

    EXPECT_EQ(a->getSessionManager(), &mgr);
}

TEST(SessionPipelineTest, ProcessPacketOnNullPacketReturnsError)
{
    Pipeline p;
    p.addHandler<NamedHandler>("A");
    FakeSession session;
    EXPECT_EQ(p.processPacket(&session, nullptr), PacketStatus::Error_NoMemory);
}

TEST(SessionPipelineTest, Clear)
{
    Pipeline p;
    p.addHandler<NamedHandler>("A");
    p.addHandler<NamedHandler>("B");
    EXPECT_EQ(p.size(), 2u);

    p.clear();
    EXPECT_TRUE(p.empty());
    EXPECT_EQ(p.size(), 0u);
    EXPECT_EQ(p.getFirst(), nullptr);
    EXPECT_EQ(p.getLast(), nullptr);
}

TEST(SessionPipelineTest, FindHandlerByName)
{
    Pipeline p;
    p.addHandler<NamedHandler>("A");
    p.addHandler<NamedHandler>("B");
    p.addHandler<NamedHandler>("C");

    Handler* found = p.findHandler("B");
    ASSERT_NE(found, nullptr);
    EXPECT_STREQ(found->name(), "B");

    EXPECT_EQ(p.findHandler("Z"), nullptr);
}

struct OtherBaseHandler : public ISessionHandler<FakeSessionManager>
{
    const char* name() const override
    {
        return "OtherBaseHandler";
    }

    PacketStatus processPacket(Session*, Packet*, PacketStatus) override
    {
        return PacketStatus::pass();
    }
};

TEST(SessionPipelineTest, FindHandlerByType)
{
    Pipeline p;
    p.addHandler<NamedHandler>("A");
    p.addHandler<AnotherHandler>();

    NamedHandler* nh = p.findHandler<NamedHandler>();
    ASSERT_NE(nh, nullptr);
    EXPECT_STREQ(nh->name(), "A");

    AnotherHandler* ah = p.findHandler<AnotherHandler>();
    ASSERT_NE(ah, nullptr);

    Handler* base = p.findHandler<Handler>();
    ASSERT_NE(base, nullptr);
    EXPECT_STREQ(base->name(), "A");

    EXPECT_EQ(p.findHandler<OtherBaseHandler>(), nullptr);
}

TEST(SessionPipelineTest, FindHandlerByTypeNotFound)
{
    Pipeline p;
    p.addHandler<AnotherHandler>();
    EXPECT_EQ(p.findHandler<NamedHandler>(), nullptr);
}

TEST(SessionPipelineTest, InsertAtBeginning)
{
    Pipeline p;
    auto a = makeHandler("A");
    auto b = makeHandler("B");
    auto c = makeHandler("C");
    p.add(a).add(b);

    EXPECT_TRUE(p.insertHandler(0, c));
    EXPECT_EQ(p.size(), 3u);
    EXPECT_EQ(p.getFirst(), c);
    EXPECT_EQ(p.getLast(), b);
}

TEST(SessionPipelineTest, InsertInMiddle)
{
    Pipeline p;
    auto a = makeHandler("A");
    auto b = makeHandler("B");
    auto c = makeHandler("C");
    p.add(a).add(b);

    EXPECT_TRUE(p.insertHandler(1, c));
    EXPECT_EQ(p.size(), 3u);
    EXPECT_EQ(p.getFirst(), a);
    EXPECT_EQ(p.getLast(), b);
}

TEST(SessionPipelineTest, InsertAtEnd)
{
    Pipeline p;
    auto a = makeHandler("A");
    auto b = makeHandler("B");
    p.add(a);

    EXPECT_TRUE(p.insertHandler(1, b));
    EXPECT_EQ(p.size(), 2u);
    EXPECT_EQ(p.getFirst(), a);
    EXPECT_EQ(p.getLast(), b);
}

TEST(SessionPipelineTest, InsertOutOfRangeReturnsFalse)
{
    Pipeline p;
    p.addHandler<NamedHandler>("A");
    auto b = makeHandler("B");

    EXPECT_FALSE(p.insertHandler(5, b));
    EXPECT_EQ(p.size(), 1u);
}

TEST(SessionPipelineTest, InsertNullptrReturnsFalse)
{
    Pipeline p;
    p.addHandler<NamedHandler>("A");
    EXPECT_FALSE(p.insertHandler(0, nullptr));
    EXPECT_EQ(p.size(), 1u);
}

TEST(SessionPipelineTest, InsertIntoEmptyAtZero)
{
    Pipeline p;
    auto a = makeHandler("A");
    EXPECT_TRUE(p.insertHandler(0, a));
    EXPECT_EQ(p.size(), 1u);
    EXPECT_EQ(p.getFirst(), a);
    EXPECT_EQ(p.getLast(), a);
}

TEST(SessionPipelineTest, RemoveHandlerFirst)
{
    Pipeline p;
    p.addHandler<NamedHandler>("A");
    p.addHandler<NamedHandler>("B");
    p.addHandler<NamedHandler>("C");

    EXPECT_TRUE(p.removeHandler("A"));
    EXPECT_EQ(p.size(), 2u);
    EXPECT_STREQ(p.getFirst()->name(), "B");
    EXPECT_STREQ(p.getLast()->name(), "C");
}

TEST(SessionPipelineTest, RemoveHandlerLast)
{
    Pipeline p;
    p.addHandler<NamedHandler>("A");
    p.addHandler<NamedHandler>("B");
    p.addHandler<NamedHandler>("C");

    EXPECT_TRUE(p.removeHandler("C"));
    EXPECT_EQ(p.size(), 2u);
    EXPECT_STREQ(p.getFirst()->name(), "A");
    EXPECT_STREQ(p.getLast()->name(), "B");
}

TEST(SessionPipelineTest, RemoveHandlerMiddle)
{
    Pipeline p;
    p.addHandler<NamedHandler>("A");
    p.addHandler<NamedHandler>("B");
    p.addHandler<NamedHandler>("C");

    EXPECT_TRUE(p.removeHandler("B"));
    EXPECT_EQ(p.size(), 2u);
    EXPECT_STREQ(p.getFirst()->name(), "A");
    EXPECT_STREQ(p.getLast()->name(), "C");
}

TEST(SessionPipelineTest, RemoveOnlyHandler)
{
    Pipeline p;
    p.addHandler<NamedHandler>("A");

    EXPECT_TRUE(p.removeHandler("A"));
    EXPECT_TRUE(p.empty());
    EXPECT_EQ(p.size(), 0u);
}

TEST(SessionPipelineTest, RemoveHandlerNotFound)
{
    Pipeline p;
    p.addHandler<NamedHandler>("A");
    p.addHandler<NamedHandler>("B");

    EXPECT_FALSE(p.removeHandler("Z"));
    EXPECT_EQ(p.size(), 2u);
}

TEST(SessionPipelineTest, RemoveHandlerFromEmpty)
{
    Pipeline p;
    EXPECT_FALSE(p.removeHandler("A"));
}

TEST(SessionPipelineTest, PrintChainDoesNotCrash)
{
    Pipeline p;
    p.addHandler<NamedHandler>("A");
    p.addHandler<NamedHandler>("B");
    p.addHandler<NamedHandler>("C");

    testing::internal::CaptureStdout();
    p.printChain(std::cout);
    std::string output = testing::internal::GetCapturedStdout();

    EXPECT_NE(output.find("A -> B -> C"), std::string::npos);
}

TEST(SessionPipelineTest, PrintChainEmpty)
{
    Pipeline p;
    testing::internal::CaptureStdout();
    p.printChain(std::cout);
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_NE(output.find("Session pipeline:"), std::string::npos);
}

TEST(SessionPipelineTest, ChainingAfterInsertAtBeginning)
{
    Pipeline p;
    auto a = makeHandler("A");
    auto b = makeHandler("B");
    auto c = makeHandler("C");
    p.add(a).add(b);

    p.insertHandler(0, c);

    EXPECT_EQ(p.getFirst(), c);
    EXPECT_EQ(p.getLast(), b);
}