#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <memory>

#include <snet/layers/packet.hpp>
#include <casket/types/intrusive_list.hpp>

namespace snet::driver
{

struct PcapPacket final : public casket::IntrusiveListNode<PcapPacket>
{
    layers::Packet packet;
    uint8_t* data;

    PcapPacket()
        : data(nullptr)
    {
    }

    ~PcapPacket() noexcept
    {
    }

    static PcapPacket* fromPacket(layers::Packet* packet)
    {
        if (!packet)
            return nullptr;

        static const size_t offset = []() -> size_t
        {
            PcapPacket dummy;
            return reinterpret_cast<size_t>(&dummy.packet) - reinterpret_cast<size_t>(&dummy);
        }();

        return reinterpret_cast<PcapPacket*>(reinterpret_cast<char*>(packet) - offset);
    }
};

class PacketPool
{
public:
    using Packet = PcapPacket;
    using FreeList = casket::IntrusiveList<Packet>;

private:
    std::vector<std::unique_ptr<uint8_t[]>> buffers_;
    std::vector<std::unique_ptr<Packet>> packets_;  // храним unique_ptr
    FreeList free_list_;
    uint64_t packets_processed_;
    uint64_t packets_dropped_;
    size_t max_packet_size_;

public:
    PacketPool(size_t pool_size, size_t max_packet_size)
        : packets_processed_(0)
        , packets_dropped_(0)
        , max_packet_size_(max_packet_size)
    {
        packets_.reserve(pool_size);
        buffers_.reserve(pool_size);

        for (size_t i = 0; i < pool_size; ++i)
        {
            // Выделяем буфер для данных
            auto buffer = std::make_unique<uint8_t[]>(max_packet_size);
            uint8_t* data_ptr = buffer.get();
            buffers_.push_back(std::move(buffer));

            // Создаём пакет через new (так как конструктор копирования удалён)
            auto packet = std::make_unique<Packet>();
            packet->data = data_ptr;

            // Добавляем в список свободных (передаём ссылку на объект)
            free_list_.push_back(*packet);
            
            // Сохраняем в вектор
            packets_.push_back(std::move(packet));
        }
    }

    Packet* acquire()
    {
        Packet* p = free_list_.pop_front();
        if (!p)
        {
            packets_dropped_++;
            return nullptr;
        }
        return p;
    }

    void release(Packet* p)
    {
        if (p)
        {
            free_list_.push_back(*p);
        }
    }

    bool fill(Packet* p, const struct pcap_pkthdr* hdr, const u_char* data)
    {
        if (!p || !hdr || !data)
            return false;

        size_t copy_size = (hdr->caplen < max_packet_size_) ? hdr->caplen : max_packet_size_;
        memcpy(p->data, data, copy_size);

        packets_processed_++;
        return true;
    }

    void clear()
    {
        // Очищаем список свободных
        while (auto* p = free_list_.pop_front())
        {
            // Просто удаляем из списка, не освобождая память
            (void)p;
        }
        
        // Восстанавливаем список свободных
        for (auto& packet_ptr : packets_)
        {
            if (packet_ptr)
            {
                packet_ptr->next = nullptr;
                packet_ptr->prev = nullptr;
                free_list_.push_back(*packet_ptr);
            }
        }
    }
    
    size_t free_count() const
    {
        return free_list_.size();
    }
    
    size_t total_count() const
    {
        return packets_.size();
    }
    
    uint64_t processed_count() const
    {
        return packets_processed_;
    }
    
    uint64_t dropped_count() const
    {
        return packets_dropped_;
    }
};

} // namespace snet::driver