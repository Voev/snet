#include <gtest/gtest.h>
#include <snet/utils/rx_ring_buffer.hpp>

using namespace snet;

TEST(RxRingBufferTest, DefaultStateIsUninitialized)
{
    RxRingBuffer rb;
    EXPECT_FALSE(rb.initialized());
    EXPECT_EQ(rb.capacity(), RxRingBuffer::DEFAULT_CAPACITY);
    EXPECT_EQ(rb.available(), 0u);
    EXPECT_EQ(rb.writeSeq(), 0u);
    EXPECT_EQ(rb.contiguousSeq(), 0u);
    EXPECT_EQ(rb.consumedSeq(), 0u);
    EXPECT_FALSE(rb.hasHole());
    EXPECT_EQ(rb.holeSize(), 0u);

    // writeAt/advanceContiguous/read/consume are no-ops before init
    uint8_t buf[4] = {1, 2, 3, 4};
    EXPECT_EQ(rb.writeAt(0, buf, 4), 0u);
    rb.advanceContiguous();
    auto p = rb.peek();
    EXPECT_EQ(p.first, nullptr);
    EXPECT_EQ(p.second, 0u);
    EXPECT_EQ(rb.read(buf, 4), 0u);
    rb.consume(4);
    EXPECT_EQ(rb.available(), 0u);
}

TEST(RxRingBufferTest, CustomCapacityIsClampedToMax)
{
    RxRingBuffer small(100);
    EXPECT_EQ(small.capacity(), 100u);

    RxRingBuffer huge(RxRingBuffer::MAX_CAPACITY * 4);
    EXPECT_EQ(huge.capacity(), RxRingBuffer::MAX_CAPACITY);
}

TEST(RxRingBufferTest, InitAtSetsFieldsAndResetsBitmap)
{
    RxRingBuffer rb(16);
    rb.initAt(1000);
    EXPECT_TRUE(rb.initialized());
    EXPECT_EQ(rb.writeSeq(), 1000u);
    EXPECT_EQ(rb.contiguousSeq(), 1000u);
    EXPECT_EQ(rb.consumedSeq(), 1000u);
    EXPECT_EQ(rb.available(), 0u);
}

// ---- Simple write/read ----

TEST(RxRingBufferTest, SimpleWriteReadRoundTrip)
{
    RxRingBuffer rb(16);
    rb.initAt(0);

    const uint8_t data[] = {1, 2, 3, 4, 5};
    EXPECT_EQ(rb.writeAt(0, data, sizeof(data)), sizeof(data));
    rb.advanceContiguous();

    EXPECT_EQ(rb.available(), sizeof(data));
    EXPECT_EQ(rb.contiguousSeq(), 5u);
    EXPECT_EQ(rb.writeSeq(), 5u);
    EXPECT_FALSE(rb.hasHole());

    uint8_t out[8] = {};
    EXPECT_EQ(rb.read(out, sizeof(out)), sizeof(data));
    EXPECT_EQ(std::memcmp(out, data, sizeof(data)), 0);
    EXPECT_EQ(rb.consumedSeq(), 5u);
    EXPECT_EQ(rb.available(), 0u);
}

TEST(RxRingBufferTest, WriteAtWithZeroLenReturnsZero)
{
    RxRingBuffer rb(16);
    rb.initAt(0);
    EXPECT_EQ(rb.writeAt(0, nullptr, 0), 0u);
}

// ---- Out-of-order / holes ----

TEST(RxRingBufferTest, OutOfOrderCreatesHole)
{
    RxRingBuffer rb(16);
    rb.initAt(0);

    const uint8_t a[] = {10, 11};
    const uint8_t b[] = {20, 21};

    // Write [4..6), then [0..2) — a hole [2..4) is created
    EXPECT_EQ(rb.writeAt(4, b, sizeof(b)), sizeof(b));
    rb.advanceContiguous();
    EXPECT_EQ(rb.available(), 0u);
    EXPECT_TRUE(rb.hasHole());
    EXPECT_EQ(rb.holeSize(), 6u); // writeSeq=6, contiguousSeq=0

    EXPECT_EQ(rb.writeAt(0, a, sizeof(a)), sizeof(a));
    rb.advanceContiguous();
    EXPECT_EQ(rb.contiguousSeq(), 2u);
    EXPECT_TRUE(rb.hasHole());

    // Close the hole
    const uint8_t gap[] = {12, 13};
    EXPECT_EQ(rb.writeAt(2, gap, sizeof(gap)), sizeof(gap));
    rb.advanceContiguous();
    EXPECT_EQ(rb.contiguousSeq(), 6u);
    EXPECT_FALSE(rb.hasHole());
    EXPECT_EQ(rb.available(), 6u);

    uint8_t out[6] = {};
    EXPECT_EQ(rb.read(out, 6), 6u);
    EXPECT_EQ(out[0], 10);
    EXPECT_EQ(out[1], 11);
    EXPECT_EQ(out[2], 12);
    EXPECT_EQ(out[3], 13);
    EXPECT_EQ(out[4], 20);
    EXPECT_EQ(out[5], 21);
}

// ---- Duplicates and partially consumed data ----

TEST(RxRingBufferTest, FullyDuplicateBehindConsumedIsRejected)
{
    RxRingBuffer rb(16);
    rb.initAt(0);
    const uint8_t d[] = {1, 2, 3, 4};
    rb.writeAt(0, d, 4);
    rb.advanceContiguous();
    uint8_t out[4];
    rb.read(out, 4); // consumedSeq = 4

    // Full duplicate [0..4) — skip >= len
    EXPECT_EQ(rb.writeAt(0, d, 4), 0u);
}

TEST(RxRingBufferTest, PartiallyDuplicateIsTrimmed)
{
    RxRingBuffer rb(16);
    rb.initAt(0);
    const uint8_t d[] = {1, 2, 3, 4, 5, 6};
    rb.writeAt(0, d, 6);
    rb.advanceContiguous();
    uint8_t out[4];
    rb.read(out, 4); // consumedSeq = 4

    // Write [2..6) — the first 2 bytes are already consumed and must be trimmed
    const uint8_t nd[] = {3, 4, 5, 6};
    EXPECT_EQ(rb.writeAt(2, nd, 4), 2u); // only 2 bytes written (seq 4,5)
    rb.advanceContiguous();
    EXPECT_EQ(rb.contiguousSeq(), 6u);

    uint8_t out2[4] = {};
    EXPECT_EQ(rb.read(out2, 4), 2u);
    EXPECT_EQ(out2[0], 5);
    EXPECT_EQ(out2[1], 6);
}

// ---- Overflow / truncation ----

TEST(RxRingBufferTest, OverflowTruncatesWrite)
{
    RxRingBuffer rb(8);
    rb.initAt(0);

    // Try to write 12 bytes with capacity=8 — at most 8 should be written
    // (ahead >= capacity => overflow = ahead - capacity + 1).
    const uint8_t data[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    size_t written = rb.writeAt(0, data, 12);
    EXPECT_LE(written, 8u);
    EXPECT_GT(written, 0u);
}

TEST(RxRingBufferTest, OverflowFullyRejectedWhenAllBeyondCapacity)
{
    RxRingBuffer rb(8);
    rb.initAt(0);

    // ahead = 100, capacity = 8 => overflow = 93 >= len=4 => 0
    const uint8_t data[4] = {1, 2, 3, 4};
    EXPECT_EQ(rb.writeAt(100, data, 4), 0u);
}

TEST(RxRingBufferTest, WriteLenLargerThanCapacityIsClamped)
{
    RxRingBuffer rb(4);
    rb.initAt(0);
    const uint8_t data[16] = {};
    size_t w = rb.writeAt(0, data, 16);
    EXPECT_LE(w, 4u);
}

// ---- Ring wrap-around ----

TEST(RxRingBufferTest, WrapAroundReadWrite)
{
    RxRingBuffer rb(8);
    rb.initAt(0);

    // Fill [0..6)
    const uint8_t d1[6] = {1, 2, 3, 4, 5, 6};
    rb.writeAt(0, d1, 6);
    rb.advanceContiguous();
    uint8_t tmp[4];
    rb.read(tmp, 4); // consumedSeq = 4, ring offset = 4

    // Write [6..10) — wraps around the ring
    const uint8_t d2[4] = {7, 8, 9, 10};
    EXPECT_EQ(rb.writeAt(6, d2, 4), 4u);
    rb.advanceContiguous();

    // Bytes 5,6,7,8,9,10 should be available
    uint8_t out[6] = {};
    EXPECT_EQ(rb.read(out, 6), 6u);
    EXPECT_EQ(out[0], 5);
    EXPECT_EQ(out[1], 6);
    EXPECT_EQ(out[2], 7);
    EXPECT_EQ(out[3], 8);
    EXPECT_EQ(out[4], 9);
    EXPECT_EQ(out[5], 10);
}

TEST(RxRingBufferTest, PeekReturnsWrappedChunk)
{
    RxRingBuffer rb(8);
    rb.initAt(0);

    // Fill the entire buffer
    const uint8_t data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    rb.writeAt(0, data, 8);
    rb.advanceContiguous();
    EXPECT_EQ(rb.available(), 8u);

    // Consume 6 — consumedSeq = 6, ring offset = 6
    rb.consume(6);
    EXPECT_EQ(rb.available(), 2u);

    // Write 4 more at [8..12) — wraps around
    const uint8_t more[4] = {9, 10, 11, 12};
    rb.writeAt(8, more, 4);
    rb.advanceContiguous();
    EXPECT_EQ(rb.available(), 6u);

    // peek must return only the first contiguous chunk up to the end of the buffer
    auto p = rb.peek();
    ASSERT_NE(p.first, nullptr);
    EXPECT_EQ(p.second, 2u); // bytes 7,8 are at offset 6,7
    EXPECT_EQ(p.first[0], 7);
    EXPECT_EQ(p.first[1], 8);
}

// ---- consume via peek (zero-copy path) ----

TEST(RxRingBufferTest, PeekThenConsume)
{
    RxRingBuffer rb(16);
    rb.initAt(0);
    const uint8_t d[] = {1, 2, 3, 4, 5};
    rb.writeAt(0, d, 5);
    rb.advanceContiguous();

    auto p = rb.peek();
    ASSERT_NE(p.first, nullptr);
    EXPECT_EQ(p.second, 5u);
    EXPECT_EQ(std::memcmp(p.first, d, 5), 0);

    rb.consume(3);
    EXPECT_EQ(rb.available(), 2u);
    EXPECT_EQ(rb.consumedSeq(), 3u);

    // consume(0) and consume(>avail) — boundary cases
    rb.consume(0);
    EXPECT_EQ(rb.consumedSeq(), 3u);
    rb.consume(100);
    EXPECT_EQ(rb.consumedSeq(), 5u);
    EXPECT_EQ(rb.available(), 0u);

    // peek with no data
    auto p2 = rb.peek();
    EXPECT_EQ(p2.first, nullptr);
    EXPECT_EQ(p2.second, 0u);

    // read with no data
    uint8_t out[4];
    EXPECT_EQ(rb.read(out, 4), 0u);
}

// ---- reset ----

TEST(RxRingBufferTest, ResetClearsState)
{
    RxRingBuffer rb(16);
    rb.initAt(100);
    const uint8_t d[] = {1, 2, 3, 4};
    rb.writeAt(100, d, 4);
    rb.advanceContiguous();
    EXPECT_EQ(rb.available(), 4u);

    rb.reset();
    EXPECT_FALSE(rb.initialized());
    EXPECT_EQ(rb.writeSeq(), 0u);
    EXPECT_EQ(rb.contiguousSeq(), 0u);
    EXPECT_EQ(rb.consumedSeq(), 0u);
    EXPECT_EQ(rb.available(), 0u);

    // After reset the buffer can be re-initialized
    rb.initAt(5);
    EXPECT_TRUE(rb.initialized());
    EXPECT_EQ(rb.writeSeq(), 5u);
}

// ---- advanceContiguous without initialized ----

TEST(RxRingBufferTest, AdvanceContiguousNoopWhenUninitialized)
{
    RxRingBuffer rb(16);
    rb.advanceContiguous();
    EXPECT_EQ(rb.contiguousSeq(), 0u);
}

// ---- 32-bit sequence number wrap-around ----

TEST(RxRingBufferTest, SequenceNumberWrapAround)
{
    RxRingBuffer rb(16);
    const uint32_t base = 0xFFFFFFF0u; // close to the uint32_t boundary
    rb.initAt(base);

    const uint8_t d1[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    EXPECT_EQ(rb.writeAt(base, d1, 8), 8u); // [0xFFFFFFF0 .. 0xFFFFFFF8)
    rb.advanceContiguous();
    EXPECT_EQ(rb.available(), 8u);

    const uint8_t d2[8] = {9, 10, 11, 12, 13, 14, 15, 16};
    EXPECT_EQ(rb.writeAt(base + 8, d2, 8), 8u); // crosses the boundary
    rb.advanceContiguous();
    EXPECT_EQ(rb.available(), 16u);

    uint8_t out[16] = {};
    EXPECT_EQ(rb.read(out, 16), 16u);
    for (int i = 0; i < 16; ++i)
        EXPECT_EQ(out[i], i + 1);
}