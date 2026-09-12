#include <gtest/gtest.h>
#include <cstdint>
#include <string>
#include <tuple>
#include <typeinfo>

#include <snet/session/session_ctx_pool_manager.hpp>

using namespace snet::session;

namespace
{

struct CtxA
{
    int value{0};
    std::string name;

    CtxA() = default;
    explicit CtxA(int v)
        : value(v)
    {
    }
    CtxA(int v, const std::string& n)
        : value(v)
        , name(n)
    {
    }
};

struct CtxB
{
    double value{0.0};
    bool flag{false};

    CtxB() = default;
    explicit CtxB(double v)
        : value(v)
    {
    }
    CtxB(double v, bool f)
        : value(v)
        , flag(f)
    {
    }
};

struct CtxC
{
    uint32_t id{0};

    CtxC() = default;
    explicit CtxC(uint32_t v)
        : id(v)
    {
    }
};

using Manager = SessionCtxPoolManager<CtxA, CtxB, CtxC>;

} // namespace

TEST(SessionCtxPoolManagerTest, DefaultConstructorUsesPoolTraitsSize)
{
    Manager m;
    EXPECT_EQ(m.capacity<CtxA>(), 8192u);
    EXPECT_EQ(m.capacity<CtxB>(), 8192u);
    EXPECT_EQ(m.capacity<CtxC>(), 8192u);
}

TEST(SessionCtxPoolManagerTest, ConstructorWithSizes)
{
    SessionCtxPoolManager<CtxA, CtxB, CtxC> m(4, 8, 16);
    EXPECT_EQ(m.capacity<CtxA>(), 4u);
    EXPECT_EQ(m.capacity<CtxB>(), 8u);
    EXPECT_EQ(m.capacity<CtxC>(), 16u);
}

TEST(SessionCtxPoolManagerTest, AllocateReturnsNonNull)
{
    SessionCtxPoolManager<CtxA, CtxB, CtxC> m(4, 4, 4);

    CtxA* a = m.allocate<CtxA>();
    CtxB* b = m.allocate<CtxB>();
    CtxC* c = m.allocate<CtxC>();

    ASSERT_NE(a, nullptr);
    ASSERT_NE(b, nullptr);
    ASSERT_NE(c, nullptr);

    m.deallocate(a);
    m.deallocate(b);
    m.deallocate(c);
}

TEST(SessionCtxPoolManagerTest, AllocateWithArgs)
{
    SessionCtxPoolManager<CtxA, CtxB, CtxC> m(4, 4, 4);

    CtxA* a = m.allocate<CtxA>(42);
    ASSERT_NE(a, nullptr);
    EXPECT_EQ(a->value, 42);

    CtxB* b = m.allocate<CtxB>(3.14, true);
    ASSERT_NE(b, nullptr);
    EXPECT_DOUBLE_EQ(b->value, 3.14);
    EXPECT_TRUE(b->flag);

    CtxC* c = m.allocate<CtxC>(7u);
    ASSERT_NE(c, nullptr);
    EXPECT_EQ(c->id, 7u);

    m.deallocate(a);
    m.deallocate(b);
    m.deallocate(c);
}

TEST(SessionCtxPoolManagerTest, AllocateWithMultipleArgs)
{
    SessionCtxPoolManager<CtxA, CtxB, CtxC> m(4, 4, 4);

    CtxA* a = m.allocate<CtxA>(1, std::string("hello"));
    ASSERT_NE(a, nullptr);
    EXPECT_EQ(a->value, 1);
    EXPECT_EQ(a->name, "hello");

    m.deallocate(a);
}

TEST(SessionCtxPoolManagerTest, DeallocateReturnsToPool)
{
    SessionCtxPoolManager<CtxA, CtxB, CtxC> m(2, 2, 2);

    CtxA* a1 = m.allocate<CtxA>();
    ASSERT_NE(a1, nullptr);
    m.deallocate(a1);

    CtxA* a2 = m.allocate<CtxA>();
    ASSERT_NE(a2, nullptr);
    EXPECT_EQ(a1, a2);

    m.deallocate(a2);
}

TEST(SessionCtxPoolManagerTest, ExhaustPool)
{
    SessionCtxPoolManager<CtxA, CtxB, CtxC> m(2, 2, 2);

    CtxA* a1 = m.allocate<CtxA>();
    CtxA* a2 = m.allocate<CtxA>();
    ASSERT_NE(a1, nullptr);
    ASSERT_NE(a2, nullptr);
    EXPECT_NE(a1, a2);

    m.deallocate(a1);
    m.deallocate(a2);
}

TEST(SessionCtxPoolManagerTest, ResetAll)
{
    SessionCtxPoolManager<CtxA, CtxB, CtxC> m(4, 4, 4);

    CtxA* a = m.allocate<CtxA>();
    CtxB* b = m.allocate<CtxB>();
    CtxC* c = m.allocate<CtxC>();

    ASSERT_NE(a, nullptr);
    ASSERT_NE(b, nullptr);
    ASSERT_NE(c, nullptr);

    m.resetAll();

    EXPECT_EQ(m.capacity<CtxA>(), 4u);
    EXPECT_EQ(m.capacity<CtxB>(), 4u);
    EXPECT_EQ(m.capacity<CtxC>(), 4u);
}

TEST(SessionCtxPoolManagerTest, CapacityIsConst)
{
    const Manager m(4, 4, 4);
    EXPECT_EQ(m.capacity<CtxA>(), 4u);
    EXPECT_EQ(m.capacity<CtxB>(), 4u);
    EXPECT_EQ(m.capacity<CtxC>(), 4u);
}

TEST(SessionCtxPoolManagerTest, PoolsAreIndependentPerType)
{
    SessionCtxPoolManager<CtxA, CtxB, CtxC> m(1, 2, 3);

    EXPECT_EQ(m.capacity<CtxA>(), 1u);
    EXPECT_EQ(m.capacity<CtxB>(), 2u);
    EXPECT_EQ(m.capacity<CtxC>(), 3u);

    CtxA* a = m.allocate<CtxA>();
    CtxB* b1 = m.allocate<CtxB>();
    CtxB* b2 = m.allocate<CtxB>();
    CtxC* c1 = m.allocate<CtxC>();
    CtxC* c2 = m.allocate<CtxC>();
    CtxC* c3 = m.allocate<CtxC>();

    ASSERT_NE(a, nullptr);
    ASSERT_NE(b1, nullptr);
    ASSERT_NE(b2, nullptr);
    ASSERT_NE(b1, b2);
    ASSERT_NE(c1, nullptr);
    ASSERT_NE(c2, nullptr);
    ASSERT_NE(c3, nullptr);

    m.deallocate(a);
    m.deallocate(b1);
    m.deallocate(b2);
    m.deallocate(c1);
    m.deallocate(c2);
    m.deallocate(c3);
}

TEST(SessionCtxPoolManagerTest, PrintStatsDoesNotCrash)
{
    Manager m(2, 2, 2);
    testing::internal::CaptureStdout();
    m.printStats();
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_FALSE(output.empty());
    EXPECT_NE(output.find("Context Pools Stats"), std::string::npos);
}

TEST(SessionCtxPoolManagerTest, PoolTraitsDefaultSize)
{
    EXPECT_EQ(PoolTraits<CtxA>::pool_size, 8192u);
    EXPECT_EQ(PoolTraits<CtxB>::pool_size, 8192u);
    EXPECT_EQ(PoolTraits<CtxC>::pool_size, 8192u);
}

TEST(SessionCtxPoolManagerTest, SingleTypeManager)
{
    SessionCtxPoolManager<CtxA> m(3);
    EXPECT_EQ(m.capacity<CtxA>(), 3u);

    CtxA* a = m.allocate<CtxA>(99);
    ASSERT_NE(a, nullptr);
    EXPECT_EQ(a->value, 99);

    m.deallocate(a);
}

TEST(SessionCtxPoolManagerTest, ReuseAfterReset)
{
    SessionCtxPoolManager<CtxA, CtxB, CtxC> m(2, 2, 2);

    CtxA* a1 = m.allocate<CtxA>();
    ASSERT_NE(a1, nullptr);

    m.resetAll();

    CtxA* a2 = m.allocate<CtxA>();
    ASSERT_NE(a2, nullptr);

    m.deallocate(a2);
}