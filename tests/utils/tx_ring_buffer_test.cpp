#include <gtest/gtest.h>
#include <snet/utils/tx_ring_buffer.hpp> 

using namespace snet;

TEST(TxRingBufferTest, DefaultStateIsUninitialized)
{
    TxRingBuffer tx;
    EXPECT_FALSE(tx.initialized());
    EXPECT_EQ(tx.pending(), 0u);
    EXPECT_EQ(tx.unacked(), 0u);
    EXPECT_EQ(tx.freeSpace(), TxRingBuffer::DEFAULT_CAPACITY);
    EXPECT_EQ(tx.seqBase(), 0u);
    EXPECT_EQ(tx.nextSeq(), 0u);
    EXPECT_EQ(tx.sndUna(), 0u);

    // All operations are no-ops before init
    const uint8_t data[4] = {1, 2, 3, 4};
    EXPECT_EQ(tx.write(data, 4), 0u);
    auto p = tx.peek();
    EXPECT_EQ(p.first, nullptr);
    EXPECT_EQ(p.second, 0u);
    tx.advance(4);
    tx.ack(4);
    tx.rewindTo(0);
    EXPECT_EQ(tx.pending(), 0u);
    EXPECT_EQ(tx.unacked(), 0u);
}

TEST(TxRingBufferTest, CustomCapacityIsClampedToMax)
{
    TxRingBuffer small(100);
    EXPECT_EQ(small.freeSpace(), 100u);

    TxRingBuffer huge(TxRingBuffer::MAX_CAPACITY * 2);
    EXPECT_EQ(huge.freeSpace(), TxRingBuffer::MAX_CAPACITY);
}

TEST(TxRingBufferTest, InitAtSetsState)
{
    TxRingBuffer tx(16);
    tx.initAt(1000);
    EXPECT_TRUE(tx.initialized());
    EXPECT_EQ(tx.seqBase(), 1000u);
    EXPECT_EQ(tx.pending(), 0u);
    EXPECT_EQ(tx.unacked(), 0u);
    EXPECT_EQ(tx.freeSpace(), 16u);
    EXPECT_EQ(tx.nextSeq(), 1000u);
    EXPECT_EQ(tx.sndUna(), 1000u);
}

// ---- write ----

TEST(TxRingBufferTest, WriteCopiesDataAndAdvancesWritePos)
{
    TxRingBuffer tx(16);
    tx.initAt(0);

    const uint8_t data[] = {1, 2, 3, 4, 5};
    EXPECT_EQ(tx.write(data, sizeof(data)), sizeof(data));
    EXPECT_EQ(tx.pending(), sizeof(data));
    EXPECT_EQ(tx.unacked(), sizeof(data));
    EXPECT_EQ(tx.freeSpace(), 16u - sizeof(data));
    EXPECT_EQ(tx.nextSeq(), 5u);
    EXPECT_EQ(tx.sndUna(), 0u);

    auto p = tx.peek();
    ASSERT_NE(p.first, nullptr);
    EXPECT_EQ(p.second, sizeof(data));
    EXPECT_EQ(std::memcmp(p.first, data, sizeof(data)), 0);
}

TEST(TxRingBufferTest, WriteToUninitializedReturnsZero)
{
    TxRingBuffer tx(16);
    const uint8_t data[4] = {};
    EXPECT_EQ(tx.write(data, 4), 0u);
}

TEST(TxRingBufferTest, WriteWithZeroLenReturnsZero)
{
    TxRingBuffer tx(16);
    tx.initAt(0);
    EXPECT_EQ(tx.write(nullptr, 0), 0u);
}

TEST(TxRingBufferTest, WriteTruncatesWhenFreeSpaceInsufficient)
{
    TxRingBuffer tx(8);
    tx.initAt(0);

    const uint8_t data[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    EXPECT_EQ(tx.write(data, 12), 8u);
    EXPECT_EQ(tx.pending(), 8u);
    EXPECT_EQ(tx.freeSpace(), 0u);

    // Further write returns 0 (toWrite == 0)
    EXPECT_EQ(tx.write(data, 4), 0u);
}

// ---- peek + advance (zero-copy send path) ----

TEST(TxRingBufferTest, PeekThenAdvance)
{
    TxRingBuffer tx(16);
    tx.initAt(0);
    const uint8_t data[] = {1, 2, 3, 4, 5};
    tx.write(data, sizeof(data));

    auto p = tx.peek();
    ASSERT_NE(p.first, nullptr);
    EXPECT_EQ(p.second, sizeof(data));

    tx.advance(3);
    EXPECT_EQ(tx.pending(), 2u);
    EXPECT_EQ(tx.unacked(), 5u); // ackedPos not moved

    // advance(0) and advance(>pending) are boundary cases
    tx.advance(0);
    EXPECT_EQ(tx.pending(), 2u);
    tx.advance(100);
    EXPECT_EQ(tx.pending(), 0u);
    EXPECT_EQ(tx.unacked(), 5u);

    // peek with no pending data
    auto p2 = tx.peek();
    EXPECT_EQ(p2.first, nullptr);
    EXPECT_EQ(p2.second, 0u);
}

// ---- ack ----

TEST(TxRingBufferTest, AckFreesSpace)
{
    TxRingBuffer tx(16);
    tx.initAt(0);
    const uint8_t data[] = {1, 2, 3, 4, 5, 6};
    tx.write(data, sizeof(data));
    EXPECT_EQ(tx.unacked(), 6u);
    EXPECT_EQ(tx.freeSpace(), 10u);

    tx.ack(4);
    EXPECT_EQ(tx.unacked(), 2u);
    EXPECT_EQ(tx.freeSpace(), 14u);
    EXPECT_EQ(tx.sndUna(), 4u);

    // ack(0) and ack(>unacked) are boundary cases
    tx.ack(0);
    EXPECT_EQ(tx.unacked(), 2u);
    tx.ack(100);
    EXPECT_EQ(tx.unacked(), 0u);
    EXPECT_EQ(tx.freeSpace(), 16u);
    EXPECT_EQ(tx.sndUna(), 6u);
}

// ---- rewindTo (retransmit) ----

TEST(TxRingBufferTest, RewindToMovesReadPos)
{
    TxRingBuffer tx(16);
    tx.initAt(0);
    const uint8_t data[] = {1, 2, 3, 4, 5, 6, 7, 8};
    tx.write(data, 8);

    // Pretend 6 bytes were sent
    tx.advance(6);
    EXPECT_EQ(tx.pending(), 2u);

    // Rewind to seq=2 (within [acked=0, write=8])
    tx.rewindTo(2);
    EXPECT_EQ(tx.pending(), 6u); // 8 - 2

    // Rewind to ackedPos_ boundary (seq=0) — allowed
    tx.rewindTo(0);
    EXPECT_EQ(tx.pending(), 8u);

    // Rewind to writePos_ (seq=8) — allowed, readPos == writePos_
    tx.rewindTo(8);
    EXPECT_EQ(tx.pending(), 0u);
}

TEST(TxRingBufferTest, RewindToRejectsBeforeSeqBase)
{
    TxRingBuffer tx(16);
    tx.initAt(100);
    const uint8_t data[] = {1, 2, 3, 4};
    tx.write(data, 4);
    tx.advance(4);

    // seq < seqBase_ => no-op
    tx.rewindTo(50);
    EXPECT_EQ(tx.pending(), 0u);

    // seq within [seqBase, seqBase+writePos] works
    tx.rewindTo(102);
    EXPECT_EQ(tx.pending(), 2u);
}

TEST(TxRingBufferTest, RewindToRejectsBelowAckedPos)
{
    TxRingBuffer tx(16);
    tx.initAt(0);
    const uint8_t data[8] = {};
    tx.write(data, 8);

    tx.ack(4);     // ackedPos = 4
    tx.advance(8); // readPos = 8, pending = 0

    // target = 2 < ackedPos_ => no-op
    tx.rewindTo(2);
    EXPECT_EQ(tx.pending(), 0u);

    // target = 4 == ackedPos_ => allowed
    tx.rewindTo(4);
    EXPECT_EQ(tx.pending(), 4u);
}

TEST(TxRingBufferTest, RewindToRejectsAboveWritePos)
{
    TxRingBuffer tx(16);
    tx.initAt(0);
    const uint8_t data[4] = {};
    tx.write(data, 4); // writePos = 4

    // target = 10 > writePos => no-op
    tx.rewindTo(10);
    EXPECT_EQ(tx.pending(), 4u);
}

TEST(TxRingBufferTest, RewindToOnUninitializedIsNoop)
{
    TxRingBuffer tx(16);
    tx.rewindTo(5); // must not crash / change anything
    EXPECT_FALSE(tx.initialized());
    EXPECT_EQ(tx.pending(), 0u);
}

// ---- ring wrap-around ----

TEST(TxRingBufferTest, WrapAroundWriteAndPeek)
{
    TxRingBuffer tx(8);
    tx.initAt(0);

    // Fill and drain to force wrap
    const uint8_t d1[6] = {1, 2, 3, 4, 5, 6};
    tx.write(d1, 6);
    tx.advance(6); // readPos = 6
    tx.ack(6);     // ackedPos = 6, free = 8

    // Write 6 more bytes — should wrap around the ring
    const uint8_t d2[6] = {7, 8, 9, 10, 11, 12};
    EXPECT_EQ(tx.write(d2, 6), 6u);
    EXPECT_EQ(tx.pending(), 6u);

    // peek returns only the first contiguous chunk up to end of buffer
    auto p = tx.peek();
    ASSERT_NE(p.first, nullptr);
    EXPECT_EQ(p.second, 2u); // offsets 6,7
    EXPECT_EQ(p.first[0], 7);
    EXPECT_EQ(p.first[1], 8);

    // Advance past the wrap, peek again for the rest
    tx.advance(2);
    auto p2 = tx.peek();
    ASSERT_NE(p2.first, nullptr);
    EXPECT_EQ(p2.second, 4u);
    EXPECT_EQ(p2.first[0], 9);
    EXPECT_EQ(p2.first[1], 10);
    EXPECT_EQ(p2.first[2], 11);
    EXPECT_EQ(p2.first[3], 12);
}

TEST(TxRingBufferTest, WriteTruncatesAtWrapBoundary)
{
    TxRingBuffer tx(8);
    tx.initAt(0);

    // Advance positions near the wrap boundary
    const uint8_t d1[7] = {1, 2, 3, 4, 5, 6, 7};
    tx.write(d1, 7);
    tx.advance(7);
    tx.ack(7); // readPos = ackedPos = 7, writePos = 7

    // Now writePos % capacity = 7; write 3 bytes wraps: 1 at offset 7, 2 at 0..1
    const uint8_t d2[3] = {10, 11, 12};
    EXPECT_EQ(tx.write(d2, 3), 3u);

    tx.rewindTo(7); // read from seq 7 again
    auto p = tx.peek();
    ASSERT_NE(p.first, nullptr);
    EXPECT_EQ(p.second, 1u); // only offset 7 before wrap
    EXPECT_EQ(p.first[0], 10);

    tx.advance(1);
    auto p2 = tx.peek();
    ASSERT_NE(p2.first, nullptr);
    EXPECT_EQ(p2.second, 2u);
    EXPECT_EQ(p2.first[0], 11);
    EXPECT_EQ(p2.first[1], 12);
}

// ---- reset ----

TEST(TxRingBufferTest, ResetClearsState)
{
    TxRingBuffer tx(16);
    tx.initAt(100);
    const uint8_t data[4] = {1, 2, 3, 4};
    tx.write(data, 4);
    tx.advance(2);
    tx.ack(1);
    EXPECT_EQ(tx.pending(), 2u);

    tx.reset();
    EXPECT_FALSE(tx.initialized());
    EXPECT_EQ(tx.seqBase(), 0u);
    EXPECT_EQ(tx.pending(), 0u);
    EXPECT_EQ(tx.unacked(), 0u);
    EXPECT_EQ(tx.freeSpace(), 16u);
    EXPECT_EQ(tx.nextSeq(), 0u);
    EXPECT_EQ(tx.sndUna(), 0u);

    // Can be re-initialized after reset
    tx.initAt(5);
    EXPECT_TRUE(tx.initialized());
    EXPECT_EQ(tx.seqBase(), 5u);
    EXPECT_EQ(tx.nextSeq(), 5u);
}

// ---- sequence number wrap-around ----

TEST(TxRingBufferTest, SequenceNumberWrapAround)
{
    TxRingBuffer tx(32);
    const uint32_t base = 0xFFFFFFF0u;
    tx.initAt(base);

    const uint8_t d1[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    EXPECT_EQ(tx.write(d1, 8), 8u);
    EXPECT_EQ(tx.nextSeq(), base + 8);
    EXPECT_EQ(tx.pending(), 8u);

    const uint8_t d2[8] = {9, 10, 11, 12, 13, 14, 15, 16};
    EXPECT_EQ(tx.write(d2, 8), 8u);     // crosses uint32 boundary
    EXPECT_EQ(tx.nextSeq(), base + 16); // wraps to 0
    EXPECT_EQ(tx.pending(), 16u);

    tx.advance(16);
    EXPECT_EQ(tx.pending(), 0u);
    tx.ack(16);
    EXPECT_EQ(tx.unacked(), 0u);
    EXPECT_EQ(tx.sndUna(), base + 16);
}

// ---- full lifecycle ----

TEST(TxRingBufferTest, FullLifecycle)
{
    TxRingBuffer tx(8);
    tx.initAt(0);

    // Fill the entire buffer
    const uint8_t d1[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    EXPECT_EQ(tx.write(d1, 8), 8u);
    EXPECT_EQ(tx.freeSpace(), 0u);

    // Send half, ack half
    tx.advance(4);
    tx.ack(4);
    EXPECT_EQ(tx.pending(), 4u);
    EXPECT_EQ(tx.unacked(), 4u);
    EXPECT_EQ(tx.freeSpace(), 4u);

    // Write 4 more (fits into freed space)
    const uint8_t d2[4] = {9, 10, 11, 12};
    EXPECT_EQ(tx.write(d2, 4), 4u);
    EXPECT_EQ(tx.pending(), 8u);
    EXPECT_EQ(tx.freeSpace(), 0u);

    // Retransmit: rewind to seq 4
    tx.rewindTo(4);
    EXPECT_EQ(tx.pending(), 8u);

    // Drain and ack everything
    tx.advance(8);
    tx.ack(8);
    EXPECT_EQ(tx.pending(), 0u);
    EXPECT_EQ(tx.unacked(), 0u);
    EXPECT_EQ(tx.freeSpace(), 8u);
    EXPECT_EQ(tx.nextSeq(), 12u);
    EXPECT_EQ(tx.sndUna(), 12u);
}