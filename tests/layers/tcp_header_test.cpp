#include <gtest/gtest.h>
#include <vector>
#include <cstring>
#include <snet/layers/l4/tcp_header_builder.hpp>
#include <snet/layers/l4/tcp_header.hpp>

using namespace snet::layers;

class TCPHeaderBuilderTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        buffer_.resize(1500);
        std::fill(buffer_.begin(), buffer_.end(), 0);
        span_ = std::span<uint8_t>(buffer_);
    }

    std::vector<uint8_t> buffer_;
    std::span<uint8_t> span_;
    const uint32_t srcIp_ = 0x0A000001; // 10.0.0.1
    const uint32_t dstIp_ = 0x0A000002; // 10.0.0.2
    const size_t headerOffset_ = 20;    // Например, после IP заголовка
};

// Тест 1: Создание билдера с корректным буфером
TEST_F(TCPHeaderBuilderTest, ConstructorWithValidBuffer)
{
    EXPECT_NO_THROW({
        TCPHeaderBuilder builder(span_, headerOffset_);
        EXPECT_TRUE(builder.isValid());
    });
}

// Тест 2: Создание билдера с некорректным буфером
TEST_F(TCPHeaderBuilderTest, ConstructorWithInvalidBuffer)
{
    std::vector<uint8_t> smallBuffer(10);
    std::span<uint8_t> smallSpan(smallBuffer);

    EXPECT_THROW({ TCPHeaderBuilder builder(smallSpan, 0); }, std::runtime_error);
}

// Тест 3: Установка source порта
TEST_F(TCPHeaderBuilderTest, SetSourcePort)
{
    TCPHeaderBuilder builder(span_, 0);
    uint16_t testPort = 8080;

    builder.setSource(testPort);

    auto* header = builder.get();
    EXPECT_EQ(be16toh(header->source), testPort);
}

// Тест 4: Установка dest порта
TEST_F(TCPHeaderBuilderTest, SetDestPort)
{
    TCPHeaderBuilder builder(span_, 0);
    uint16_t testPort = 443;

    builder.setDest(testPort);

    auto* header = builder.get();
    EXPECT_EQ(be16toh(header->dest), testPort);
}

// Тест 5: Установка sequence number
TEST_F(TCPHeaderBuilderTest, SetSeqNum)
{
    TCPHeaderBuilder builder(span_, 0);
    uint32_t testSeq = 0x12345678;

    builder.setSeq(testSeq);

    auto* header = builder.get();
    EXPECT_EQ(be32toh(header->seq), testSeq);
}

// Тест 6: Установка acknowledgment number
TEST_F(TCPHeaderBuilderTest, SetAckSeq)
{
    TCPHeaderBuilder builder(span_, 0);
    uint32_t testAck = 0x87654321;

    builder.setAckSeq(testAck);

    auto* header = builder.get();
    EXPECT_EQ(be32toh(header->ack_seq), testAck);
}

// Тест 7: Установка data offset
TEST_F(TCPHeaderBuilderTest, SetDoff)
{
    TCPHeaderBuilder builder(span_, 0);
    uint8_t testDoff = 8;

    builder.setDoff(testDoff);

    auto* header = builder.get();
    EXPECT_EQ(header->doff, testDoff);
}

// Тест 8: Установка флагов через setFlags
TEST_F(TCPHeaderBuilderTest, SetFlags)
{
    TCPHeaderBuilder builder(span_, 0);
    uint8_t testFlags = 0x3F; // Все флаги установлены (FIN, SYN, RST, PSH, ACK, URG)

    builder.setFlags(testFlags);

    auto* header = builder.get();
    EXPECT_EQ(header->fin, 1);
    EXPECT_EQ(header->syn, 1);
    EXPECT_EQ(header->rst, 1);
    EXPECT_EQ(header->psh, 1);
    EXPECT_EQ(header->ack, 1);
    EXPECT_EQ(header->urg, 1);
}

// Тест 9: Установка отдельных флагов
TEST_F(TCPHeaderBuilderTest, SetIndividualFlags)
{
    TCPHeaderBuilder builder(span_, 0);

    builder.setSyn(true).setAck(true).setFin(false);

    auto* header = builder.get();
    EXPECT_EQ(header->syn, 1);
    EXPECT_EQ(header->ack, 1);
    EXPECT_EQ(header->fin, 0);
}

// Тест 10: Сброс флагов
TEST_F(TCPHeaderBuilderTest, ResetFlags)
{
    TCPHeaderBuilder builder(span_, 0);

    builder.setSyn(true).setSyn(false);

    auto* header = builder.get();
    EXPECT_EQ(header->syn, 0);
}

// Тест 11: Установка window
TEST_F(TCPHeaderBuilderTest, SetWindow)
{
    TCPHeaderBuilder builder(span_, 0);
    uint16_t testWindow = 65535;

    builder.setWindow(testWindow);

    auto* header = builder.get();
    EXPECT_EQ(be16toh(header->window), testWindow);
}

// Тест 12: Установка urgent pointer
TEST_F(TCPHeaderBuilderTest, SetUrgPtr)
{
    TCPHeaderBuilder builder(span_, 0);
    uint16_t testUrg = 100;

    builder.setUrgPtr(testUrg);

    auto* header = builder.get();
    EXPECT_EQ(be16toh(header->urg_ptr), testUrg);
}

// Тест 13: Цепочка вызовов (fluent interface)
TEST_F(TCPHeaderBuilderTest, FluentInterface)
{
    TCPHeaderBuilder builder(span_, 0);

    builder.setSource(8080).setDest(443).setSeq(1000).setAckSeq(2000).setSyn(true).setAck(true).setWindow(8192);

    auto* header = builder.get();
    EXPECT_EQ(be16toh(header->source), 8080);
    EXPECT_EQ(be16toh(header->dest), 443);
    EXPECT_EQ(be32toh(header->seq), 1000);
    EXPECT_EQ(be32toh(header->ack_seq), 2000);
    EXPECT_EQ(header->syn, 1);
    EXPECT_EQ(header->ack, 1);
    EXPECT_EQ(be16toh(header->window), 8192);
}

// Тест 14: Копирование из существующего TCPHeader
TEST_F(TCPHeaderBuilderTest, FromHeader)
{
    // Создаем исходный заголовок
    TCPHeaderBuilder sourceBuilder(span_, 0);
    sourceBuilder.setSource(8080).setDest(443).setSeq(1000).setAckSeq(2000).setSyn(true).setAck(true).setWindow(8192);

    // Получаем TCPHeader
    TCPHeader sourceHeader = sourceBuilder.getHeader();

    // Создаем новый билдер и копируем из заголовка
    std::vector<uint8_t> newBuffer(1500);
    std::span<uint8_t> newSpan(newBuffer);
    TCPHeaderBuilder newBuilder(newSpan, 0);
    newBuilder.fromHeader(sourceHeader);

    // Проверяем, что все скопировалось корректно
    auto* header = newBuilder.get();
    EXPECT_EQ(be16toh(header->source), 8080);
    EXPECT_EQ(be16toh(header->dest), 443);
    EXPECT_EQ(be32toh(header->seq), 1000);
    EXPECT_EQ(be32toh(header->ack_seq), 2000);
    EXPECT_EQ(header->syn, 1);
    EXPECT_EQ(header->ack, 1);
    EXPECT_EQ(be16toh(header->window), 8192);
}

// Тест 15: Копирование с опциями
TEST_F(TCPHeaderBuilderTest, FromHeaderWithOptions)
{
    // TODO: Добавить тест с опциями TCP
    // Для этого нужно создать заголовок с опциями и проверить их копирование
}

// Тест 16: Расчет контрольной суммы
TEST_F(TCPHeaderBuilderTest, CalculateChecksum)
{
    TCPHeaderBuilder builder(span_, headerOffset_);
    builder.setSource(8080).setDest(443).setSeq(1000).setAckSeq(2000).setSyn(true).setAck(true).setWindow(8192).setDoff(
        5);

    size_t tcpLen = 20; // Без опций
    size_t totalLen = headerOffset_ + tcpLen;

    builder.build(totalLen, srcIp_, dstIp_, true);

    auto* header = builder.get();
    EXPECT_NE(header->check, 0); // Контрольная сумма не должна быть нулевой
}

// Тест 17: Автоматический расчет контрольной суммы при build
TEST_F(TCPHeaderBuilderTest, AutoChecksumOnBuild)
{
    TCPHeaderBuilder builder(span_, headerOffset_);
    builder.setSource(8080).setDest(443).setSeq(1000).setAckSeq(2000).setSyn(true).setAck(true).setWindow(8192).setDoff(
        5);

    size_t tcpLen = 20;
    size_t totalLen = headerOffset_ + tcpLen;

    // Сначала check = 0
    auto* header = builder.get();
    EXPECT_EQ(header->check, 0);

    // После build с autoChecksum = true контрольная сумма должна быть рассчитана
    builder.build(totalLen, srcIp_, dstIp_, true);
    EXPECT_NE(header->check, 0);
}

// Тест 18: Build без автоматической контрольной суммы
TEST_F(TCPHeaderBuilderTest, BuildWithoutAutoChecksum)
{
    TCPHeaderBuilder builder(span_, headerOffset_);
    builder.setSource(8080).setDest(443).setDoff(5);

    size_t tcpLen = 20;
    size_t totalLen = headerOffset_ + tcpLen;

    auto* header = builder.get();
    header->check = 0x1234; // Устанавливаем явно

    builder.build(totalLen, srcIp_, dstIp_, false);
    EXPECT_EQ(header->check, 0x1234); // Должно сохраниться наше значение
}

// Тест 19: Получение TCPHeader
TEST_F(TCPHeaderBuilderTest, GetHeader)
{
    TCPHeaderBuilder builder(span_, 0);
    builder.setSource(8080).setDest(443).setSyn(true);

    TCPHeader header = builder.getHeader();
    EXPECT_TRUE(header.isValid());
    EXPECT_EQ(header.srcPort(), 8080);
    EXPECT_EQ(header.dstPort(), 443);
    EXPECT_TRUE(header.isSYN());
}

// Тест 20: Header size
TEST_F(TCPHeaderBuilderTest, HeaderSize)
{
    TCPHeaderBuilder builder(span_, 0);

    builder.setDoff(5);
    EXPECT_EQ(builder.getHeaderSize(), 20);

    builder.setDoff(8);
    EXPECT_EQ(builder.getHeaderSize(), 32);
}

// Тест 21: Reset
TEST_F(TCPHeaderBuilderTest, Reset)
{
    TCPHeaderBuilder builder(span_, 0);
    builder.setSource(8080).setDest(443).setSyn(true);

    size_t tcpLen = 20;
    size_t totalLen = headerOffset_ + tcpLen;
    builder.build(totalLen, srcIp_, dstIp_, true);

    EXPECT_TRUE(builder.isBuilt());

    builder.reset();

    EXPECT_FALSE(builder.isBuilt());
    // Проверяем, что после сброса можно снова использовать билдер
    builder.setSource(80).setDest(443).setSyn(true);
    EXPECT_NO_THROW({ builder.build(totalLen, srcIp_, dstIp_, true); });
}

// Тест 22: GetPacketSpan
TEST_F(TCPHeaderBuilderTest, GetPacketSpan)
{
    TCPHeaderBuilder builder(span_, 0);

    auto span = builder.getPacketSpan();
    EXPECT_EQ(span.size(), buffer_.size());

    const auto constSpan = builder.getPacketSpan();
    EXPECT_EQ(constSpan.size(), buffer_.size());
}

// Тест 23: GetBufferSize и GetHeaderOffset
TEST_F(TCPHeaderBuilderTest, GetBufferSizeAndOffset)
{
    TCPHeaderBuilder builder(span_, headerOffset_);

    EXPECT_EQ(builder.getBufferSize(), buffer_.size());
    EXPECT_EQ(builder.getHeaderOffset(), headerOffset_);
}

// Тест 24: Multiple builds (двойной build должен вернуть тот же span)
TEST_F(TCPHeaderBuilderTest, MultipleBuilds)
{
    TCPHeaderBuilder builder(span_, headerOffset_);
    builder.setSource(8080).setDest(443).setDoff(5);

    size_t tcpLen = 20;
    size_t totalLen = headerOffset_ + tcpLen;

    auto result1 = builder.build(totalLen, srcIp_, dstIp_, true);
    auto result2 = builder.build(totalLen, srcIp_, dstIp_, false);

    EXPECT_EQ(result1.size(), result2.size());
    EXPECT_EQ(result1.data(), result2.data());
}

// Тест 25: Проверка валидности после создания
TEST_F(TCPHeaderBuilderTest, IsValid)
{
    TCPHeaderBuilder builder(span_, 0);
    EXPECT_TRUE(builder.isValid());

    // Создаем невалидный билдер (маленький буфер)
    std::vector<uint8_t> smallBuffer(10);
    std::span<uint8_t> smallSpan(smallBuffer);
    EXPECT_THROW({ TCPHeaderBuilder invalidBuilder(smallSpan, 0); }, std::runtime_error);
}