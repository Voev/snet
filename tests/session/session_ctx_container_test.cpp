#include <gtest/gtest.h>
#include <cstdint>
#include <string>
#include <vector>

#include <snet/session/session_ctx_container.hpp>

using namespace snet::session;

namespace
{

struct CtxA
{
    static constexpr size_t MAX_INSTANCES = 1;
    int value{0};
    bool destroyed{false};
    ~CtxA()
    {
        destroyed = true;
    }
};

struct CtxB
{
    static constexpr size_t MAX_INSTANCES = 2;
    int value{0};
    bool destroyed{false};
    ~CtxB()
    {
        destroyed = true;
    }
};

struct CtxC
{
    static constexpr size_t MAX_INSTANCES = 3;
    double value{0.0};
};

using Container = SessionCtxContainer<CtxA, CtxB, CtxC>;

} // namespace

TEST(SessionCtxContainerTest, Constants)
{
    EXPECT_EQ(Container::CONTEXT_COUNT, 3u);
    EXPECT_EQ(Container::MAX_INSTANCES, 3u);
}

TEST(SessionCtxContainerTest, DefaultConstructedIsEmpty)
{
    Container c;
    EXPECT_TRUE(c.empty());
    EXPECT_EQ(c.activeCount(), 0u);
    EXPECT_EQ(c.slotMask(), 0u);
}

TEST(SessionCtxContainerTest, GetOnEmptyReturnsNull)
{
    Container c;
    EXPECT_EQ(c.get<CtxA>(), nullptr);
    EXPECT_EQ(c.get<CtxB>(), nullptr);
    EXPECT_EQ(c.get<CtxB>(1), nullptr);
    EXPECT_EQ(c.get<CtxC>(), nullptr);
}

TEST(SessionCtxContainerTest, SetAndGet)
{
    Container c;
    CtxA a;
    a.value = 42;

    EXPECT_TRUE(c.set<CtxA>(&a));
    EXPECT_FALSE(c.empty());
    EXPECT_EQ(c.activeCount(), 1u);

    CtxA* got = c.get<CtxA>();
    ASSERT_NE(got, nullptr);
    EXPECT_EQ(got->value, 42);
    EXPECT_EQ(got, &a);

    EXPECT_EQ(c.get<CtxB>(), nullptr);
}

TEST(SessionCtxContainerTest, SetNullReturnsFalse)
{
    Container c;
    EXPECT_FALSE(c.set<CtxA>(nullptr));
    EXPECT_TRUE(c.empty());
    EXPECT_EQ(c.activeCount(), 0u);
}

TEST(SessionCtxContainerTest, SetMultipleTypes)
{
    Container c;
    CtxA a;
    CtxB b0, b1;
    CtxC cc;

    EXPECT_TRUE(c.set<CtxA>(&a));
    EXPECT_TRUE(c.set<CtxB>(&b0, 0));
    EXPECT_TRUE(c.set<CtxB>(&b1, 1));
    EXPECT_TRUE(c.set<CtxC>(&cc));

    EXPECT_EQ(c.activeCount(), 4u);
    EXPECT_EQ(c.get<CtxA>(), &a);
    EXPECT_EQ(c.get<CtxB>(0), &b0);
    EXPECT_EQ(c.get<CtxB>(1), &b1);
    EXPECT_EQ(c.get<CtxC>(), &cc);
}

TEST(SessionCtxContainerTest, SetOutOfRangeIndexReturnsFalse)
{
    Container c;
    CtxA a;
    EXPECT_FALSE(c.set<CtxA>(&a, 1));
    EXPECT_TRUE(c.empty());

    CtxC cc;
    EXPECT_FALSE(c.set<CtxC>(&cc, 3));
    EXPECT_TRUE(c.empty());
}

TEST(SessionCtxContainerTest, CtxAOverwritesCtxBSlot)
{
    Container c;
    CtxA a;  a.value = 111;
    CtxB b;  b.value = 222;

    // Легально кладём CtxB в его слот 0
    EXPECT_TRUE(c.set<CtxB>(&b, 0));

    // Нелегальный индекс для CtxA (MAX_INSTANCES=1) — не должен проходить
    EXPECT_FALSE(c.set<CtxA>(&a, 1));

    // Если CtxB всё ещё на месте — всё ок
    EXPECT_EQ(c.get<CtxB>(0), &b);
    EXPECT_EQ(c.get<CtxB>(0)->value, 222);
}

TEST(SessionCtxContainerTest, SetSamePointerTwiceDoesNotDoubleCount)
{
    Container c;
    CtxA a;
    EXPECT_TRUE(c.set<CtxA>(&a));
    EXPECT_EQ(c.activeCount(), 1u);

    EXPECT_TRUE(c.set<CtxA>(&a));
    EXPECT_EQ(c.activeCount(), 1u);
}

TEST(SessionCtxContainerTest, SetReplacesExistingDifferentPointer)
{
    Container c;
    CtxA a1, a2;

    EXPECT_TRUE(c.set<CtxA>(&a1));
    EXPECT_EQ(c.activeCount(), 1u);
    EXPECT_FALSE(a1.destroyed);

    EXPECT_TRUE(c.set<CtxA>(&a2));
    EXPECT_EQ(c.activeCount(), 1u);
    EXPECT_TRUE(a1.destroyed);
    EXPECT_FALSE(a2.destroyed);
    EXPECT_EQ(c.get<CtxA>(), &a2);
}

TEST(SessionCtxContainerTest, Has)
{
    Container c;
    CtxA a;
    CtxB b;

    EXPECT_FALSE(c.has<CtxA>());
    EXPECT_FALSE(c.has<CtxA>(0));

    c.set<CtxA>(&a);
    c.set<CtxB>(&b, 1);

    EXPECT_TRUE(c.has<CtxA>());
    EXPECT_FALSE(c.has<CtxA>(1));
    EXPECT_FALSE(c.has<CtxB>(0));
    EXPECT_TRUE(c.has<CtxB>(1));
    EXPECT_FALSE(c.has<CtxC>());
}

TEST(SessionCtxContainerTest, HasOutOfRangeReturnsFalse)
{
    Container c;
    EXPECT_FALSE(c.has<CtxA>(1));
    EXPECT_FALSE(c.has<CtxC>(3));
}

TEST(SessionCtxContainerTest, Clear)
{
    Container c;
    CtxA a;
    c.set<CtxA>(&a);

    EXPECT_TRUE(c.clear<CtxA>());
    EXPECT_TRUE(c.empty());
    EXPECT_EQ(c.get<CtxA>(), nullptr);
    EXPECT_TRUE(a.destroyed);
}

TEST(SessionCtxContainerTest, ClearEmptyReturnsFalse)
{
    Container c;
    EXPECT_FALSE(c.clear<CtxA>());
    EXPECT_FALSE(c.clear<CtxB>(1));
}

TEST(SessionCtxContainerTest, ClearOutOfRangeReturnsFalse)
{
    Container c;
    CtxA a;
    c.set<CtxA>(&a);
    EXPECT_FALSE(c.clear<CtxA>(1));
    EXPECT_EQ(c.activeCount(), 1u);
}

TEST(SessionCtxContainerTest, ClearOnlyOneInstance)
{
    Container c;
    CtxB b0, b1;
    c.set<CtxB>(&b0, 0);
    c.set<CtxB>(&b1, 1);

    EXPECT_TRUE(c.clear<CtxB>(0));
    EXPECT_EQ(c.activeCount(), 1u);
    EXPECT_TRUE(b0.destroyed);
    EXPECT_FALSE(b1.destroyed);
    EXPECT_FALSE(c.has<CtxB>(0));
    EXPECT_TRUE(c.has<CtxB>(1));
}

TEST(SessionCtxContainerTest, ClearAll)
{
    Container c;
    CtxA a;
    CtxB b0, b1;
    CtxC cc;

    c.set<CtxA>(&a);
    c.set<CtxB>(&b0, 0);
    c.set<CtxB>(&b1, 1);
    c.set<CtxC>(&cc);

    EXPECT_EQ(c.activeCount(), 4u);

    c.clearAll();

    EXPECT_TRUE(c.empty());
    EXPECT_EQ(c.activeCount(), 0u);
    EXPECT_EQ(c.slotMask(), 0u);
    EXPECT_EQ(c.get<CtxA>(), nullptr);
    EXPECT_EQ(c.get<CtxB>(0), nullptr);
    EXPECT_EQ(c.get<CtxB>(1), nullptr);
    EXPECT_EQ(c.get<CtxC>(), nullptr);
}

TEST(SessionCtxContainerTest, ClearAllOnEmpty)
{
    Container c;
    c.clearAll();
    EXPECT_TRUE(c.empty());
    EXPECT_EQ(c.activeCount(), 0u);
}

TEST(SessionCtxContainerTest, ForEachVisitsAllActive)
{
    Container c;
    CtxA a;
    CtxB b;
    CtxC cc;
    c.set<CtxA>(&a);
    c.set<CtxB>(&b, 0);
    c.set<CtxC>(&cc);

    size_t count = 0;
    c.forEach(
        [&](uint32_t, void* data)
        {
            ASSERT_NE(data, nullptr);
            ++count;
        });
    EXPECT_EQ(count, 3u);
}

TEST(SessionCtxContainerTest, ForEachOnEmptyDoesNothing)
{
    Container c;
    size_t count = 0;
    c.forEach(
        [&](uint32_t, void*)
        {
            ++count;
        });
    EXPECT_EQ(count, 0u);
}

TEST(SessionCtxContainerTest, SlotMaskUpdates)
{
    Container c;
    CtxA a;
    EXPECT_EQ(c.slotMask(), 0u);

    c.set<CtxA>(&a);
    EXPECT_NE(c.slotMask(), 0u);

    uint32_t mask_after_set = c.slotMask();
    c.clear<CtxA>();
    EXPECT_EQ(c.slotMask(), 0u);
    EXPECT_NE(mask_after_set, 0u);
}

TEST(SessionCtxContainerTest, GetTypeIdIsStableAndDistinct)
{
    uint32_t id_a1 = Container::getTypeId<CtxA>();
    uint32_t id_a2 = Container::getTypeId<CtxA>();
    uint32_t id_b = Container::getTypeId<CtxB>();
    uint32_t id_c = Container::getTypeId<CtxC>();

    EXPECT_EQ(id_a1, id_a2);
    EXPECT_NE(id_a1, id_b);
    EXPECT_NE(id_a1, id_c);
    EXPECT_NE(id_b, id_c);
}

TEST(SessionCtxContainerTest, InstanceIndexingPerTypeIsolated)
{
    Container c;
    CtxA a;
    CtxB b0, b1;

    c.set<CtxA>(&a, 0);
    c.set<CtxB>(&b0, 0);
    c.set<CtxB>(&b1, 1);

    EXPECT_EQ(c.get<CtxA>(0), &a);
    EXPECT_EQ(c.get<CtxB>(0), &b0);
    EXPECT_EQ(c.get<CtxB>(1), &b1);

    EXPECT_EQ(c.get<CtxA>(1), nullptr);
    EXPECT_EQ(c.get<CtxC>(0), nullptr);
}

TEST(SessionCtxContainerTest, ReSetAfterClear)
{
    Container c;
    CtxA a1, a2;

    c.set<CtxA>(&a1);
    c.clear<CtxA>();
    EXPECT_TRUE(c.empty());

    c.set<CtxA>(&a2);
    EXPECT_EQ(c.activeCount(), 1u);
    EXPECT_EQ(c.get<CtxA>(), &a2);
}

TEST(SessionCtxContainerTest, NonTriviallyDestructibleTypeHandling)
{
    Container c;
    CtxC cc;
    c.set<CtxC>(&cc);
    EXPECT_EQ(c.get<CtxC>(), &cc);
    EXPECT_TRUE(c.clear<CtxC>());
    EXPECT_TRUE(c.empty());
}