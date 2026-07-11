#pragma once

#include <span>
#include <cstring>
#include <endian.h>
#include <stdexcept>
#include <snet/layers/l4/tcp_header.hpp>

namespace snet::layers
{

class TCPHeaderBuilder
{
private:
    tcp_header* header_;
    std::span<uint8_t> packetSpan_;
    size_t headerOffset_;
    bool isBuilt_ = false;
    uint32_t pseudoHeaderSum_ = 0;

    // Структура псевдозаголовка для IPv4
    struct PseudoHeader
    {
        uint32_t src;
        uint32_t dst;
        uint8_t zeros;
        uint8_t protocol;
        uint16_t tcpLen;
    } __attribute__((packed));

public:
    TCPHeaderBuilder(std::span<uint8_t> buffer, size_t offset = 0)
        : packetSpan_(buffer)
        , headerOffset_(offset)
    {
        if (buffer.size() >= sizeof(tcp_header) + offset)
        {
            header_ = reinterpret_cast<tcp_header*>(buffer.data() + offset);
        }
        else
        {
            throw std::runtime_error("Buffer too small for TCP header");
        }
    }

    // Методы установки полей заголовка
    TCPHeaderBuilder& setSource(uint16_t port)
    {
        header_->source = htobe16(port);
        return *this;
    }

    TCPHeaderBuilder& setDest(uint16_t port)
    {
        header_->dest = htobe16(port);
        return *this;
    }

    TCPHeaderBuilder& setSeq(uint32_t seqNum)
    {
        header_->seq = htobe32(seqNum);
        return *this;
    }

    TCPHeaderBuilder& setAckSeq(uint32_t ackNum)
    {
        header_->ack_seq = htobe32(ackNum);
        return *this;
    }

    TCPHeaderBuilder& setDoff(uint8_t dataOffset = 5)
    {
        header_->doff = dataOffset;
        return *this;
    }

    // Установка всех флагов одним байтом (битовый формат: CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
    TCPHeaderBuilder& setFlags(uint8_t flags)
    {
        header_->fin = flags & 0x01;
        header_->syn = (flags >> 1) & 0x01;
        header_->rst = (flags >> 2) & 0x01;
        header_->psh = (flags >> 3) & 0x01;
        header_->ack = (flags >> 4) & 0x01;
        header_->urg = (flags >> 5) & 0x01;
        return *this;
    }

    // Удобные методы для установки отдельных флагов
    TCPHeaderBuilder& setSyn(bool set = true)
    {
        header_->syn = set ? 1 : 0;
        return *this;
    }

    TCPHeaderBuilder& setAck(bool set = true)
    {
        header_->ack = set ? 1 : 0;
        return *this;
    }

    TCPHeaderBuilder& setFin(bool set = true)
    {
        header_->fin = set ? 1 : 0;
        return *this;
    }

    TCPHeaderBuilder& setRst(bool set = true)
    {
        header_->rst = set ? 1 : 0;
        return *this;
    }

    TCPHeaderBuilder& setPsh(bool set = true)
    {
        header_->psh = set ? 1 : 0;
        return *this;
    }

    TCPHeaderBuilder& setUrg(bool set = true)
    {
        header_->urg = set ? 1 : 0;
        return *this;
    }

    TCPHeaderBuilder& setWindow(uint16_t window)
    {
        header_->window = htobe16(window);
        return *this;
    }

    TCPHeaderBuilder& setCheck(uint16_t checksum)
    {
        header_->check = checksum;
        return *this;
    }

    TCPHeaderBuilder& setUrgPtr(uint16_t urgent)
    {
        header_->urg_ptr = htobe16(urgent);
        return *this;
    }

    // Метод для копирования значений из существующего TCPHeader
    TCPHeaderBuilder& fromHeader(const TCPHeader& header)
    {
        if (!header.isValid())
        {
            throw std::runtime_error("Cannot copy from invalid TCP header");
        }

        const auto* raw = header.raw();
        if (!raw)
        {
            throw std::runtime_error("Raw header is null");
        }

        // Копируем все поля из TCPHeader
        header_->source = raw->source;
        header_->dest = raw->dest;
        header_->seq = raw->seq;
        header_->ack_seq = raw->ack_seq;
        header_->doff = raw->doff;
        header_->fin = raw->fin;
        header_->syn = raw->syn;
        header_->rst = raw->rst;
        header_->psh = raw->psh;
        header_->ack = raw->ack;
        header_->urg = raw->urg;
        header_->res1 = raw->res1;
        header_->res2 = raw->res2;
        header_->window = raw->window;
        header_->check = raw->check;
        header_->urg_ptr = raw->urg_ptr;

        // Копирование опций, если они есть
        size_t optionsLen = header.optionsLength();
        if (optionsLen > 0)
        {
            uint8_t* destOptions = reinterpret_cast<uint8_t*>(header_) + sizeof(tcp_header);
            const uint8_t* srcOptions = header.options();
            if (srcOptions)
            {
                std::memcpy(destOptions, srcOptions, optionsLen);
            }
        }

        return *this;
    }

    // Установка псевдозаголовка для расчета контрольной суммы
    TCPHeaderBuilder& setPseudoHeader(uint32_t srcIp, uint32_t dstIp, uint16_t tcpLen)
    {
        // Используем обычный массив вместо packed структуры
        uint8_t pseudoBuffer[12];

        // Заполняем псевдозаголовок
        uint32_t* pseudoSrc = reinterpret_cast<uint32_t*>(pseudoBuffer);
        uint32_t* pseudoDst = reinterpret_cast<uint32_t*>(pseudoBuffer + 4);
        uint8_t* pseudoZeros = pseudoBuffer + 8;
        uint8_t* pseudoProtocol = pseudoBuffer + 9;
        uint16_t* pseudoTcpLen = reinterpret_cast<uint16_t*>(pseudoBuffer + 10);

        *pseudoSrc = srcIp;
        *pseudoDst = dstIp;
        *pseudoZeros = 0;
        *pseudoProtocol = 6; // IPPROTO_TCP
        *pseudoTcpLen = htobe16(tcpLen);

        // Накапливаем сумму псевдозаголовка
        uint32_t sum = 0;
        const uint16_t* ptr = reinterpret_cast<const uint16_t*>(pseudoBuffer);
        for (size_t i = 0; i < 6; ++i) // 12 байт / 2 = 6 слов
        {
            sum += be16toh(ptr[i]);
            if (sum & 0x80000000)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }
        pseudoHeaderSum_ = sum;
        return *this;
    }

    // Расчет контрольной суммы TCP (включая псевдозаголовок)
    uint16_t calculateChecksum(uint32_t srcIp, uint32_t dstIp, size_t tcpLen)
    {
        // Собираем псевдозаголовок в обычный массив для безопасного доступа
        uint8_t pseudoBuffer[12];
        uint32_t* pseudoSrc = reinterpret_cast<uint32_t*>(pseudoBuffer);
        uint32_t* pseudoDst = reinterpret_cast<uint32_t*>(pseudoBuffer + 4);
        uint8_t* pseudoZeros = pseudoBuffer + 8;
        uint8_t* pseudoProtocol = pseudoBuffer + 9;
        uint16_t* pseudoTcpLen = reinterpret_cast<uint16_t*>(pseudoBuffer + 10);

        *pseudoSrc = srcIp;
        *pseudoDst = dstIp;
        *pseudoZeros = 0;
        *pseudoProtocol = 6; // IPPROTO_TCP
        *pseudoTcpLen = htobe16(static_cast<uint16_t>(tcpLen));

        // Накапливаем сумму псевдозаголовка
        uint32_t sum = 0;
        const uint16_t* ptr = reinterpret_cast<const uint16_t*>(pseudoBuffer);
        for (size_t i = 0; i < 6; ++i) // 12 байт / 2 = 6 слов
        {
            sum += be16toh(ptr[i]);
            if (sum & 0x80000000)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }

        // Добавляем TCP заголовок
        const uint16_t* tcpPtr = reinterpret_cast<const uint16_t*>(header_);
        size_t words = (tcpLen + 1) / 2;

        for (size_t i = 0; i < words; ++i)
        {
            uint16_t val = (i * 2 + 1 < tcpLen) ? be16toh(tcpPtr[i]) : 0;
            sum += val;
            if (sum & 0x80000000)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }

        while (sum >> 16)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return htobe16(~sum & 0xFFFF);
    }

    std::span<uint8_t> build(size_t totalLen, uint32_t srcIp, uint32_t dstIp, bool autoChecksum = true)
    {
        if (!isBuilt_)
        {
            // Убеждаемся, что data offset установлен (по умолчанию 5)
            if (header_->doff == 0)
            {
                header_->doff = 5;
            }

            if (autoChecksum)
            {
                size_t tcpLen = totalLen - headerOffset_;
                header_->check = 0;
                header_->check = calculateChecksum(srcIp, dstIp, tcpLen);
            }

            isBuilt_ = true;
        }
        return packetSpan_.subspan(0, totalLen);
    }

    // Получение сырого заголовка
    tcp_header* get()
    {
        return header_;
    }

    const tcp_header* get() const
    {
        return header_;
    }

    // Получение TCPHeader для чтения
    TCPHeader getHeader() const
    {
        return TCPHeader::fromRaw(header_);
    }

    // Размер заголовка в байтах
    size_t getHeaderSize() const
    {
        return header_->doff * 4;
    }

    // Проверка валидности
    bool isValid() const
    {
        return header_ != nullptr;
    }

    // Получение размера буфера
    size_t getBufferSize() const
    {
        return packetSpan_.size();
    }

    // Получение смещения заголовка
    size_t getHeaderOffset() const
    {
        return headerOffset_;
    }

    // Проверка, собран ли заголовок
    bool isBuilt() const
    {
        return isBuilt_;
    }

    // Сброс состояния (для переиспользования)
    void reset()
    {
        isBuilt_ = false;
        pseudoHeaderSum_ = 0;
    }

    // Получение спана пакета
    std::span<uint8_t> getPacketSpan()
    {
        return packetSpan_;
    }

    std::span<const uint8_t> getPacketSpan() const
    {
        return packetSpan_;
    }
};

} // namespace snet::layers